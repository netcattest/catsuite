package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestSignedResourceUploadReuseScopeAndRelease(t *testing.T) {
	b, s, c := setupBridge(t)
	c = pairedClient(t, b, s, c)
	data := []byte(`{"openapi":"3.1.0","paths":{"/api/valid":{"get":{"responses":{"200":{"description":"OK"}}}}}}`)
	input := Resource{Flow: testID, Revision: strings.Repeat("a", 64), Protection: "PUBLIC", SHA256: hash(data), Bytes: len(data), Chunks: 1}
	code, value := requestTest(t, c, "POST", s.URL+"/v2/resources", input)
	if code != 201 {
		t.Fatal(value)
	}
	id := value["id"].(string)
	code, value = requestTest(t, c, "POST", s.URL+"/v2/resources/"+id+"/chunks/0", map[string]string{"data": base64.StdEncoding.EncodeToString(data)})
	if code != 200 {
		t.Fatal(value)
	}
	code, value = requestTest(t, c, "POST", s.URL+"/v2/resources", input)
	if code != 200 || value["id"] != id || value["received"].(float64) != 1 {
		t.Fatal(value)
	}
	code, value = requestTest(t, c, "POST", s.URL+"/v2/resources/"+id+"/commit", map[string]any{})
	if code != 200 {
		t.Fatal(value)
	}
	code, value = requestTest(t, c, "POST", s.URL+"/v2/resources", input)
	if code != 200 || value["committed"] != true {
		t.Fatal(value)
	}
	job := JobRequest{Resource: id, Flow: testID, Revision: input.Revision, Protection: "PUBLIC", Parameters: &ToolParameters{Operations: []string{"GET /api/valid"}, Paths: []string{"/api/valid"}, Methods: []string{"GET"}}}
	if _, e := b.resourceFor(job, testID); e != nil {
		t.Fatal(e)
	}
	if _, e := b.resourceFor(job, "other-device"); e == nil {
		t.Fatal("cross device")
	}
	job.Revision = strings.Repeat("b", 64)
	if _, e := b.resourceFor(job, testID); e == nil {
		t.Fatal("cross revision")
	}
	b.mu.Lock()
	b.jobs["active"] = &Job{Resource: id, Status: "paused"}
	b.mu.Unlock()
	code, _ = requestTest(t, c, "POST", s.URL+"/v2/resources/"+id+"/release", map[string]any{})
	if code != 409 {
		t.Fatal("released paused resource")
	}
	b.mu.Lock()
	b.jobs["active"].Status = "complete"
	b.mu.Unlock()
	code, value = requestTest(t, c, "POST", s.URL+"/v2/resources/"+id+"/release", map[string]any{})
	if code != 200 {
		t.Fatal(value)
	}
}
func TestResourceIntegrityAndPagination(t *testing.T) {
	b, s, c := setupBridge(t)
	c = pairedClient(t, b, s, c)
	input := Resource{Flow: testID, Revision: strings.Repeat("a", 64), Protection: "SECRET", SHA256: hash([]byte("{}")), Bytes: 2, Chunks: 1}
	_, value := requestTest(t, c, "POST", s.URL+"/v2/resources", input)
	id := value["id"].(string)
	requestTest(t, c, "POST", s.URL+"/v2/resources/"+id+"/chunks/0", map[string]string{"data": base64.StdEncoding.EncodeToString([]byte("[]"))})
	code, value := requestTest(t, c, "POST", s.URL+"/v2/resources/"+id+"/commit", map[string]any{})
	if code != 400 || value["error"] != "E_INTEGRITY" {
		t.Fatal(value)
	}
	lines := []json.RawMessage{}
	for i := 0; i < 101; i++ {
		lines = append(lines, json.RawMessage(`{"kind":"analysis"}`))
	}
	b.mu.Lock()
	b.jobs["page"] = &Job{ID: "page", Owner: testID, Flow: testID, Results: lines, Status: "complete"}
	b.mu.Unlock()
	code, value = requestTest(t, c, "GET", s.URL+"/v2/jobs/page/results?cursor=0", nil)
	if code != 200 || len(value["results"].([]any)) != 50 || value["nextCursor"].(float64) != 50 {
		t.Fatal(value)
	}
	code, value = requestTest(t, c, "GET", s.URL+"/v2/jobs/page/results?cursor=100", nil)
	if code != 200 || len(value["results"].([]any)) != 1 {
		t.Fatal(value)
	}
	code, _ = requestTest(t, c, "GET", s.URL+"/v2/jobs/page/results?cursor=102", nil)
	if code != 400 {
		t.Fatal(code)
	}
}
func TestSchemaEventsKeepMinimumCaseWithoutCredentialsOrPayload(t *testing.T) {
	job := brokerJob("https://aurora.test")
	job.Tool = "schemathesis"
	job.Parameters.Operations = []string{"GET /api/broken"}
	job.Headers = []SharedHeader{{Name: "Authorization", Value: "private-value"}}
	events := `{"ScenarioFinished":{"is_final":true,"recorder":{"interactions":{"case":{"request":{"uri":"https://aurora.test/api/broken?token=private-value","method":"GET","headers":{"authorization":"private-value"},"body":"private-value"},"response":{"status_code":200,"content":"private-value"}}},"checks":{"case":[{"name":"response_schema_conformance","status":"failure","failure_info":{"failure":{"type":"JsonSchemaError","message":"private-value"}}}]}}}}
{"EngineFinished":{}}
`
	results, e := schemaEvents(strings.NewReader(events), job, strings.Repeat("a", 64))
	if e != nil {
		t.Fatal(e)
	}
	if len(results) != 1 || strings.Contains(string(results[0]), "private-value") || !strings.Contains(string(results[0]), "contract-failure") || !strings.Contains(string(results[0]), "minimized") {
		t.Fatal(string(results[0]))
	}
	if _, e = schemaEvents(strings.NewReader(`{"FatalError":{}}`), job, ""); e == nil {
		t.Fatal("fatal error accepted")
	}
}
