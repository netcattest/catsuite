package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Resource struct {
	Kind       string `json:"kind,omitempty"`
	ID         string `json:"id"`
	Owner      string `json:"owner"`
	Flow       string `json:"flow"`
	Revision   string `json:"revision"`
	Protection string `json:"protection"`
	SHA256     string `json:"sha256"`
	Bytes      int    `json:"bytes"`
	Chunks     int    `json:"chunks"`
	Received   int    `json:"received"`
	Committed  bool   `json:"committed"`
	Created    int64  `json:"created"`
}

func (b *Bridge) resourcePath(id string) string { return filepath.Join(b.directory, "resources", id) }
func (b *Bridge) getResource(id, owner string) (Resource, error) {
	var r Resource
	if !idPattern.MatchString(id) {
		return r, errors.New("E_RESOURCE")
	}
	if b.readPrivate(filepath.Join(b.resourcePath(id), "meta.json"), &r) != nil || r.Owner != owner || r.ID != id {
		return r, errors.New("E_RESOURCE")
	}
	return r, nil
}
func (b *Bridge) resourceData(r Resource) ([]byte, error) {
	out := []byte{}
	for i := 0; i < r.Chunks; i++ {
		var chunk struct {
			Data string `json:"data"`
		}
		if b.readPrivate(filepath.Join(b.resourcePath(r.ID), strconv.Itoa(i)+".json"), &chunk) != nil {
			return nil, errors.New("E_RESOURCE")
		}
		data, e := base64.StdEncoding.Strict().DecodeString(chunk.Data)
		if e != nil || len(data) > 65536 || len(out)+len(data) > 2*1024*1024 {
			return nil, errors.New("E_SIZE")
		}
		out = append(out, data...)
	}
	if len(out) != r.Bytes || hash(out) != r.SHA256 {
		return nil, errors.New("E_INTEGRITY")
	}
	return out, nil
}
func schemaDocument(data []byte) (map[string]any, error) {
	if len(data) == 0 || len(data) > 2*1024*1024 {
		return nil, errors.New("E_SIZE")
	}
	depth, quoted, escaped := 0, false, false
	for _, c := range data {
		if quoted {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				quoted = false
			}
			continue
		}
		if c == '"' {
			quoted = true
		} else if c == '{' || c == '[' {
			depth++
			if depth > 64 {
				return nil, errors.New("E_SIZE")
			}
		} else if c == '}' || c == ']' {
			depth--
		}
	}
	var doc map[string]any
	if json.Unmarshal(data, &doc) != nil {
		return nil, errors.New("E_SCHEMA")
	}
	version, _ := doc["openapi"].(string)
	swagger, _ := doc["swagger"].(string)
	if !(strings.HasPrefix(version, "3.0.") || strings.HasPrefix(version, "3.1.") || swagger == "2.0") {
		return nil, errors.New("E_SCHEMA")
	}
	nodes := 0
	var walk func(any, int) error
	walk = func(value any, depth int) error {
		nodes++
		if nodes > 100000 || depth > 64 {
			return errors.New("E_SIZE")
		}
		switch v := value.(type) {
		case map[string]any:
			for key, item := range v {
				if key == "$ref" {
					ref, ok := item.(string)
					if !ok || !strings.HasPrefix(ref, "#/") {
						return errors.New("E_SCHEMA_REFERENCE")
					}
				}
				if e := walk(item, depth+1); e != nil {
					return e
				}
			}
		case []any:
			for _, item := range v {
				if e := walk(item, depth+1); e != nil {
					return e
				}
			}
		}
		return nil
	}
	if e := walk(doc, 0); e != nil {
		return nil, e
	}
	if _, ok := doc["paths"].(map[string]any); !ok {
		return nil, errors.New("E_SCHEMA")
	}
	return doc, nil
}
func (b *Bridge) resourceFor(input JobRequest, owner string) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	r, e := b.getResource(input.Resource, owner)
	if e != nil {
		return nil, e
	}
	if !r.Committed || r.Flow != input.Flow || r.Revision != input.Revision || r.Protection != input.Protection {
		return nil, errors.New("E_DATA_APPROVAL")
	}
	data, e := b.resourceData(r)
	if e != nil {
		return nil, e
	}
	if ecosystemResource(input.Capability) != "" {
		if r.Kind != ecosystemResource(input.Capability) {
			return nil, errors.New("E_RESOURCE")
		}
		if _, err := ecosystemResourceDocument(data, r.Kind); err != nil {
			return nil, err
		}
		return data, nil
	}
	doc, e := schemaDocument(data)
	if e != nil {
		return nil, e
	}
	paths := doc["paths"].(map[string]any)
	for i, operation := range input.Parameters.Operations {
		parts := strings.SplitN(operation, " ", 2)
		if len(parts) != 2 || parts[1] != input.Parameters.Paths[i] {
			return nil, errors.New("E_SCHEMA_OPERATION")
		}
		allowed := false
		for _, method := range input.Parameters.Methods {
			if parts[0] == method {
				allowed = true
			}
		}
		path, _ := paths[parts[1]].(map[string]any)
		if !allowed || path[strings.ToLower(parts[0])] == nil {
			return nil, errors.New("E_SCHEMA_OPERATION")
		}
	}
	return data, nil
}
func (b *Bridge) resourceRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v2/resources", func(w http.ResponseWriter, r *http.Request) {
		owner, e := b.owner(r)
		if e != nil {
			fail(w, 403, "E_PAIRING_REVOKED")
			return
		}
		var input Resource
		if decode(w, r, &input) != nil || !resourceKindValid(input.Kind) || !idPattern.MatchString(input.SHA256) || !idPattern.MatchString(input.Revision) || !regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`).MatchString(input.Flow) || input.Bytes < 1 || input.Bytes > 2*1024*1024 || input.Chunks != (input.Bytes+65535)/65536 || (input.Protection != "PUBLIC" && input.Protection != "PROTECTED" && input.Protection != "SECRET") {
			fail(w, 400, "E_RESOURCE")
			return
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		input.Owner = owner
		input.ID = hash([]byte(owner + ":" + input.Flow + ":" + input.Revision + ":" + input.Protection + ":" + input.SHA256))
		if previous, err := b.getResource(input.ID, owner); err == nil {
			if previous.Bytes != input.Bytes || previous.Chunks != input.Chunks || strings.TrimPrefix(previous.Kind, "openapi") != strings.TrimPrefix(input.Kind, "openapi") {
				fail(w, 409, "E_INTEGRITY")
				return
			}
			response(w, 200, map[string]any{"id": previous.ID, "chunkBytes": 65536, "received": previous.Received, "committed": previous.Committed})
			return
		}
		directory := filepath.Join(b.directory, "resources")
		os.MkdirAll(directory, 0700)
		files, e := os.ReadDir(directory)
		if e == nil {
			for _, entry := range files {
				if !entry.IsDir() || !idPattern.MatchString(entry.Name()) {
					continue
				}
				var old Resource
				if b.readPrivate(filepath.Join(directory, entry.Name(), "meta.json"), &old) != nil || old.ID != entry.Name() || old.Created > time.Now().Add(-24*time.Hour).Unix() {
					continue
				}
				busy := false
				for _, job := range b.jobs {
					if job.Resource == old.ID && job.Status != "complete" && job.Status != "error" && job.Status != "cancelled" {
						busy = true
					}
				}
				if !busy {
					os.RemoveAll(b.resourcePath(old.ID))
				}
			}
			files, e = os.ReadDir(directory)
		}
		if e != nil || len(files) >= 32 {
			fail(w, 429, "E_RESOURCE_QUOTA")
			return
		}
		input.Received = 0
		input.Committed = false
		input.Created = time.Now().Unix()
		if os.Mkdir(b.resourcePath(input.ID), 0700) != nil || b.writePrivate(filepath.Join(b.resourcePath(input.ID), "meta.json"), input) != nil {
			fail(w, 500, "E_STORAGE")
			return
		}
		response(w, 201, map[string]any{"id": input.ID, "chunkBytes": 65536, "received": 0, "committed": false})
	})
	mux.HandleFunc("POST /v2/resources/{id}/chunks/{index}", func(w http.ResponseWriter, r *http.Request) {
		owner, e := b.owner(r)
		if e != nil {
			fail(w, 403, "E_PAIRING_REVOKED")
			return
		}
		var input struct {
			Data string `json:"data"`
		}
		if decode(w, r, &input) != nil {
			fail(w, 400, "E_RESOURCE")
			return
		}
		data, e := base64.StdEncoding.Strict().DecodeString(input.Data)
		index, ie := strconv.Atoi(r.PathValue("index"))
		if e != nil || ie != nil || len(data) < 1 || len(data) > 65536 {
			fail(w, 400, "E_SIZE")
			return
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		resource, e := b.getResource(r.PathValue("id"), owner)
		if e != nil || resource.Committed || index != resource.Received || index >= resource.Chunks || len(data) != min(65536, resource.Bytes-index*65536) {
			fail(w, 409, "E_RESOURCE")
			return
		}
		if b.writePrivate(filepath.Join(b.resourcePath(resource.ID), strconv.Itoa(index)+".json"), input) != nil {
			fail(w, 500, "E_STORAGE")
			return
		}
		resource.Received++
		if b.writePrivate(filepath.Join(b.resourcePath(resource.ID), "meta.json"), resource) != nil {
			fail(w, 500, "E_STORAGE")
			return
		}
		response(w, 200, map[string]int{"received": resource.Received})
	})
	mux.HandleFunc("POST /v2/resources/{id}/commit", func(w http.ResponseWriter, r *http.Request) {
		owner, e := b.owner(r)
		if e != nil {
			fail(w, 403, "E_PAIRING_REVOKED")
			return
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		resource, e := b.getResource(r.PathValue("id"), owner)
		if e != nil || resource.Received != resource.Chunks {
			fail(w, 400, "E_RESOURCE")
			return
		}
		data, e := b.resourceData(resource)
		if e != nil {
			fail(w, 400, e.Error())
			return
		}
		if resource.Kind == "" || resource.Kind == "openapi" {
			_, e = schemaDocument(data)
		} else {
			_, e = ecosystemResourceDocument(data, resource.Kind)
		}
		if e != nil {
			fail(w, 400, e.Error())
			return
		}
		resource.Committed = true
		if b.writePrivate(filepath.Join(b.resourcePath(resource.ID), "meta.json"), resource) != nil {
			fail(w, 500, "E_STORAGE")
			return
		}
		response(w, 200, map[string]any{"id": resource.ID, "sha256": resource.SHA256, "bytes": resource.Bytes, "committed": true})
	})
	mux.HandleFunc("POST /v2/resources/{id}/release", func(w http.ResponseWriter, r *http.Request) {
		owner, e := b.owner(r)
		if e != nil {
			fail(w, 403, "E_PAIRING_REVOKED")
			return
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		resource, e := b.getResource(r.PathValue("id"), owner)
		if e != nil {
			fail(w, 404, "E_RESOURCE")
			return
		}
		for _, job := range b.jobs {
			if job.Resource == resource.ID && job.Status != "complete" && job.Status != "error" && job.Status != "cancelled" {
				fail(w, 409, "E_JOB_STATE")
				return
			}
		}
		if os.RemoveAll(b.resourcePath(resource.ID)) != nil {
			fail(w, 500, "E_STORAGE")
			return
		}
		response(w, 200, map[string]bool{"released": true})
	})
}
func (b *Bridge) resultRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v2/jobs/{id}/results", func(w http.ResponseWriter, r *http.Request) {
		owner, e := b.owner(r)
		if e != nil {
			fail(w, 403, "E_PAIRING_REVOKED")
			return
		}
		offset := 0
		if value := r.URL.Query().Get("cursor"); value != "" {
			offset, e = strconv.Atoi(value)
		}
		if e != nil || offset < 0 || offset > 1000 {
			fail(w, 400, "E_CURSOR")
			return
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		job := b.jobs[r.PathValue("id")]
		if job == nil || job.Owner != owner {
			fail(w, 404, "E_JOB")
			return
		}
		if offset > len(job.Results) {
			fail(w, 400, "E_CURSOR")
			return
		}
		end := offset
		size := 0
		for end < len(job.Results) && end-offset < 50 && size+len(job.Results[end]) <= 512*1024 {
			size += len(job.Results[end])
			end++
		}
		response(w, 200, map[string]any{"id": job.ID, "flow": job.Flow, "revision": job.Revision, "node": job.Node, "capability": job.Capability, "protection": job.Protection, "definitionHash": job.DefinitionHash, "results": job.Results[offset:end], "nextCursor": end, "total": len(job.Results), "status": job.Status})
	})
}
