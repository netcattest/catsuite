package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSingleHostLockAndRelease(t *testing.T) {
	dir := t.TempDir()
	release, e := acquireHostLock(dir)
	if e != nil {
		t.Fatal(e)
	}
	if other, e := acquireHostLock(dir); e == nil {
		other()
		t.Fatal("Concurrent host accepted")
	}
	release()
	next, e := acquireHostLock(dir)
	if e != nil {
		t.Fatal(e)
	}
	next()
}
func TestEncryptedJobStateHidesContentAndAuthenticatesFileIdentity(t *testing.T) {
	b, _, _ := setupBridge(t)
	path := filepath.Join(b.directory, "private.json")
	input := map[string]string{"secret": "fictional-private-marker"}
	if e := b.writePrivate(path, input); e != nil {
		t.Fatal(e)
	}
	bytes, e := os.ReadFile(path)
	if e != nil || strings.Contains(string(bytes), "fictional-private-marker") {
		t.Fatal("Plaintext state")
	}
	var recovered map[string]string
	if e := b.readPrivate(path, &recovered); e != nil || recovered["secret"] != input["secret"] {
		t.Fatal(e)
	}
	other := filepath.Join(b.directory, "other.json")
	os.WriteFile(other, bytes, 0600)
	if b.readPrivate(other, &recovered) == nil {
		t.Fatal("Relocated ciphertext")
	}
	var doc map[string]any
	json.Unmarshal(bytes, &doc)
	value := doc["ciphertext"].(string)
	prefix := "A"
	if value[0] == 'A' {
		prefix = "B"
	}
	doc["ciphertext"] = prefix + value[1:]
	writeJSON(path, doc)
	if b.readPrivate(path, &recovered) == nil {
		t.Fatal("Altered ciphertext")
	}
}
func TestDeterministicBatchesSkipCompletedAndRequireUnknownRetry(t *testing.T) {
	input := JobRequest{Targets: []string{"f", "e", "d", "c", "b", "a"}}
	templates := []Template{{ID: "6"}, {ID: "5"}, {ID: "4"}, {ID: "3"}, {ID: "2"}, {ID: "1"}}
	batches := planBatches(input, templates)
	if len(batches) != 4 {
		t.Fatal(len(batches))
	}
	for _, batch := range batches {
		if len(batch.Targets) > 5 || len(batch.Templates) > 5 {
			t.Fatal("Oversized batch")
		}
	}
	reversed := planBatches(JobRequest{Targets: []string{"a", "b", "c", "d", "e", "f"}}, templates)
	for i, b := range batches {
		if b.ID != reversed[i].ID {
			t.Fatal("Unstable batch")
		}
	}
	b, _, _ := setupBridge(t)
	valid := validJob(b)
	chosen, _ := b.validateJob(valid)
	job := &Job{ID: strings.Repeat("a", 64), Batches: planBatches(valid, chosen)}
	job.Batches[0].Status = "unknown"
	if e := b.executeBatches(context.Background(), valid, chosen, job, func(json.RawMessage) error { return nil }); e == nil || e.Error() != "E_UNKNOWN_RESULT" {
		t.Fatal(e)
	}
	calls := 0
	b.execute = func(context.Context, JobRequest, []Template, func(json.RawMessage) error) error { calls++; return nil }
	valid.RetryUnknown = true
	if e := b.executeBatches(context.Background(), valid, chosen, job, func(json.RawMessage) error { return nil }); e != nil {
		t.Fatal(e)
	}
	if e := b.executeBatches(context.Background(), valid, chosen, job, func(json.RawMessage) error { return nil }); e != nil || calls != 1 {
		t.Fatal("Repeated completed batch", e, calls)
	}
}
