package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"time"
)

type Batch struct {
	ID        string   `json:"id"`
	Status    string   `json:"status"`
	Targets   []string `json:"targets"`
	Templates []string `json:"templates"`
	Results   int      `json:"results"`
}

func planBatches(input JobRequest, templates []Template) []Batch {
	targets := append([]string{}, input.Targets...)
	sort.Strings(targets)
	ids := []string{}
	for _, template := range templates {
		ids = append(ids, template.ID)
	}
	sort.Strings(ids)
	batches := []Batch{}
	for i := 0; i < len(targets); i += 5 {
		for j := 0; j < len(ids); j += 5 {
			t := append([]string{}, targets[i:min(i+5, len(targets))]...)
			m := append([]string{}, ids[j:min(j+5, len(ids))]...)
			body, _ := json.Marshal([][]string{t, m})
			batches = append(batches, Batch{ID: hash(body), Status: "pending", Targets: t, Templates: m})
		}
	}
	return batches
}
func (b *Bridge) executeBatches(ctx context.Context, input JobRequest, templates []Template, job *Job, emit func(json.RawMessage) error) error {
	for index := range job.Batches {
		b.mu.Lock()
		batch := job.Batches[index]
		b.mu.Unlock()
		if batch.Status == "complete" {
			continue
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if batch.Status == "unknown" && !input.RetryUnknown {
			return errors.New("E_UNKNOWN_RESULT")
		}
		chosen := []Template{}
		for _, id := range batch.Templates {
			for _, t := range templates {
				if t.ID == id {
					chosen = append(chosen, t)
				}
			}
		}
		local := input
		local.Targets = batch.Targets
		if input.Capability == "nuclei.scan" {
			local.TemplateIDs = batch.Templates
		} else if input.Tool == "schemathesis" {
			p := *input.Parameters
			p.Operations = []string{batch.Templates[0]}
			p.Paths = []string{batch.Templates[1]}
			local.Parameters = &p
		}
		if input.Capability != "nuclei.scan" {
			b.mu.Lock()
			pending := 0
			for _, candidate := range job.Batches[index:] {
				if candidate.Status != "complete" {
					pending++
				}
			}
			p := *local.Parameters
			p.Requests = (input.Parameters.Requests - job.RequestsReserved) / pending
			if input.Tool == "katana" {
				p.Pages = (input.Parameters.Pages - job.PagesReserved) / pending
			}
			b.mu.Unlock()
			if p.Requests < 1 || input.Tool == "katana" && p.Pages < 1 {
				return errors.New("E_REQUEST_BUDGET")
			}
			local.Parameters = &p
		}
		if _, e := b.validateJob(local); e != nil {
			return e
		}
		b.mu.Lock()
		job.Batches[index].Status = "running"
		if input.Capability != "nuclei.scan" {
			job.RequestsReserved += local.Parameters.Requests
			if input.Tool == "katana" {
				job.PagesReserved += local.Parameters.Pages
			}
		}
		e := b.persistJob(job)
		b.mu.Unlock()
		if e != nil {
			return errors.New("E_STORAGE")
		}
		lines := []json.RawMessage{}
		size := 0
		executor := b.execute
		if input.Capability != "nuclei.scan" {
			executor = func(ctx context.Context, input JobRequest, _ []Template, emit func(json.RawMessage) error) error {
				return b.executeTool(ctx, input, job.Owner, emit)
			}
		}
		e = executor(ctx, local, chosen, func(line json.RawMessage) error {
			size += len(line)
			if size > 768*1024 || len(lines) >= 1000 || !json.Valid(line) || len(line) > 128*1024 {
				return errors.New("E_RESULT")
			}
			lines = append(lines, append(json.RawMessage{}, line...))
			return nil
		})
		if e == nil {
			for _, line := range lines {
				if e = emit(line); e != nil {
					break
				}
			}
		}
		b.mu.Lock()
		job.Batches[index].Status = "complete"
		job.Batches[index].Results = len(lines)
		if e != nil {
			job.Batches[index].Status = "error"
			if ctx.Err() != nil {
				job.Batches[index].Status = "unknown"
			}
		}
		storageError := b.persistJob(job)
		b.mu.Unlock()
		if storageError != nil {
			return errors.New("E_STORAGE")
		}
		if e != nil {
			return e
		}
	}
	return nil
}
func (b *Bridge) resumeJob(w http.ResponseWriter, r *http.Request) {
	owner, e := b.owner(r)
	if e != nil {
		fail(w, 403, "E_PAIRING_REVOKED")
		return
	}
	var input JobRequest
	if decode(w, r, &input) != nil || input.ID != r.PathValue("id") {
		fail(w, 400, "E_JOB")
		return
	}
	templates, e := b.validateJob(input)
	if e == nil {
		e = b.verifyAuthorization(input, owner)
	}
	if e != nil {
		fail(w, 403, e.Error())
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	job := b.jobs[input.ID]
	if job == nil || job.Owner != owner || job.Digest != jobDefinition(input) {
		fail(w, 403, "E_AUTHORIZATION")
		return
	}
	if job.Status != "paused" && job.Status != "interrupted" {
		fail(w, 409, "E_JOB_STATE")
		return
	}
	for _, batch := range job.Batches {
		if batch.Status == "unknown" && !input.RetryUnknown {
			fail(w, 409, "E_UNKNOWN_RESULT")
			return
		}
	}
	remaining := time.Duration(input.Timeout)*time.Second - time.Duration(job.Spent)*time.Millisecond
	if remaining <= 0 {
		fail(w, 409, "E_TIMEOUT")
		return
	}
	select {
	case b.slots <- struct{}{}:
	default:
		fail(w, 429, "E_QUEUE")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), remaining)
	job.cancel = cancel
	job.pauseRequested = false
	job.Status = "running"
	job.Error = ""
	job.Finished = 0
	job.lease = time.Now().Add(15 * time.Second)
	if e = b.persistJob(job); e != nil {
		cancel()
		<-b.slots
		fail(w, 500, "E_STORAGE")
		return
	}
	response(w, 202, job)
	go b.launch(job, input, templates, ctx, cancel)
}
