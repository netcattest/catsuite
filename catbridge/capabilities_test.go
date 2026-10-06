package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func brokerJob(target string) JobRequest {
	return JobRequest{ID: strings.Repeat("a", 64), Flow: "00000000-0000-4000-8000-000000000001", Revision: strings.Repeat("b", 64), Node: "probe", Tool: "katana", Capability: "web.crawl", Protection: "PUBLIC", Targets: []string{target}, Scope: []string{target}, Rate: 5, Timeout: 120, Parameters: &ToolParameters{Profile: "read-only", Methods: []string{"GET", "HEAD"}, Requests: 10, Pages: 25, Depth: 2}}
}
func TestCapabilityCatalogContracts(t *testing.T) {
	b := &Bridge{}
	seen := map[string]bool{}
	for _, c := range b.catalog() {
		if seen[c.ID] || c.Title["pt-BR"] == "" || c.Title["en"] == "" || len(c.Inputs) == 0 || len(c.Outputs) == 0 || c.Contract != map[bool]int{true: 2, false: 1}[c.Stage > 1] {
			t.Fatal(c)
		}
		seen[c.ID] = true
		if c.Stage > 1 && c.State != "not-installed" {
			t.Fatal(c.State)
		}
	}
	if len(seen) != 23 {
		t.Fatal(len(seen))
	}
	if _, e := normalizeToolParameters([]byte(`{"profile":"read-only","methods":["GET"],"requests":5,"shell":"whoami"}`)); e == nil {
		t.Fatal("unknown parameter accepted")
	}
}
func TestHTTPBrokerTLSMethodsScopeAndBudget(t *testing.T) {
	var sent atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent.Add(1)
		if r.Header.Get("Authorization") != "" {
			t.Error("unapproved credentials")
		}
		w.Header().Set("X-Lab", "origin")
		io.WriteString(w, "fixture")
	}))
	defer upstream.Close()
	target := upstream.URL
	job := brokerJob(target)
	job.Parameters.Requests = 2
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw})
	broker, e := newHTTPBroker(BrokerPolicy{Job: job, HostScope: job.Scope, CA: string(ca)})
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewServer(broker)
	defer server.Close()
	proxy, _ := url.Parse(server.URL)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(broker.pem)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy), TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, method := range []string{"POST", "GET", "GET", "GET"} {
		request, _ := http.NewRequest(method, target+"/api/perfil", nil)
		request.Header.Set("Authorization", "Bearer test-only")
		response, e := client.Do(request)
		if e != nil {
			t.Fatal(e)
		}
		data, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if method == "POST" && response.StatusCode != 403 {
			t.Fatal("method allowed")
		}
		if method == "GET" && response.StatusCode == 200 && string(data) != "fixture" {
			t.Fatal(string(data))
		}
	}
	if sent.Load() != 2 {
		t.Fatal(sent.Load())
	}
	var summary map[string]any
	json.Unmarshal(broker.summary(), &summary)
	if summary["upstreamTLS"].(map[string]any)[canonicalOrigin(mustURL(target))] != hash(upstream.Certificate().Raw) {
		t.Fatal(summary)
	}
	request, _ := http.NewRequest("GET", "https://example.invalid/", nil)
	if _, e = client.Do(request); e == nil {
		t.Fatal("outside origin connected")
	}
}
func mustURL(value string) *url.URL { u, _ := url.Parse(value); return u }
func TestHTTPBrokerOperationPaths(t *testing.T) {
	job := brokerJob("https://api.aurora.test/base")
	job.Tool = "schemathesis"
	job.Capability = "api.schema.test"
	job.Parameters.Paths = []string{"/users/{id}"}
	job.Parameters.Operations = []string{"GET /users/{id}"}
	broker, e := newHTTPBroker(BrokerPolicy{Job: job, HostScope: job.Scope})
	if e != nil {
		t.Fatal(e)
	}
	if !broker.permits(mustURL("https://api.aurora.test/base/users/123"), "GET") || broker.permits(mustURL("https://api.aurora.test/base/admin"), "GET") || broker.permits(mustURL("https://api.aurora.test/base/users/123"), "DELETE") || broker.permits(mustURL("https://api.aurora.test/base/users/../admin"), "GET") {
		t.Fatal("operation boundary")
	}
}
func TestSchemaLimitsAndExternalReferences(t *testing.T) {
	if _, e := schemaDocument([]byte(strings.Repeat("[", 65) + strings.Repeat("]", 65))); e == nil {
		t.Fatal("nested schema accepted")
	}
	for _, schema := range []string{`{"openapi":"3.1.0","paths":{},"components":{"schemas":{"x":{"$ref":"https://evil.invalid/schema"}}}}`, `{"openapi":"3.2.0","paths":{}}`, `{"paths":{}}`} {
		if _, e := schemaDocument([]byte(schema)); e == nil {
			t.Fatal(schema)
		}
	}
	if _, e := schemaDocument([]byte(`{"openapi":"3.1.0","paths":{"/api/perfil":{"get":{"responses":{"200":{"description":"OK"}}}}}}`)); e != nil {
		t.Fatal(e)
	}
}
func TestToolNormalizationAndRedaction(t *testing.T) {
	if value := sanitizeURL("https://private-user:private-password@api.aurora.test/?code=private-code#private-fragment"); strings.Contains(value, "private-") {
		t.Fatal(value)
	}
	job := brokerJob("https://api.aurora.test")
	job.Tool = "httpx"
	data, e := normalizeToolResult(job, []byte(`{"url":"https://api.aurora.test/?access_token=fictitious","status_code":200,"title":"Aurora","header":{"server":"fixture","set_cookie":"private"},"request":"private","tls":{"subject_cn":"internal broker"}}`))
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(data), "fictitious") || strings.Contains(string(data), "private") || strings.Contains(string(data), "internal broker") {
		t.Fatal(string(data))
	}
	job.Tool = "katana"
	data, e = normalizeToolResult(job, []byte(`{"request":{"endpoint":"https://api.aurora.test/api/perfil","method":"GET","source":"https://api.aurora.test/app.js"},"response":{"status_code":200,"body":"private"}}`))
	if e != nil || !strings.Contains(string(data), `"fetched":true`) || strings.Contains(string(data), "private") {
		t.Fatal(string(data), e)
	}
	job.Headers = []SharedHeader{{Name: "Authorization", Value: "Bearer fictional-credential"}, {Name: "Cookie", Value: "session=fictional-cookie"}}
	job.Tool = "httpx"
	data, e = normalizeToolResult(job, []byte(`{"url":"https://api.aurora.test/","title":"fictional-credential","location":"https://api.aurora.test/?token=fictional-cookie","header":{"server":"fictional-credential"}}`))
	if e != nil || strings.Contains(string(data), "fictional-credential") || strings.Contains(string(data), "fictional-cookie") {
		t.Fatal(string(data), e)
	}
}
func TestCrawlerKeepsFormsAndDistinguishesBrokerDenial(t *testing.T) {
	job := brokerJob("https://api.aurora.test")
	data, e := normalizeToolResult(job, []byte(`{"request":{"endpoint":"https://api.aurora.test/?q=1","method":"GET"},"response":{"status_code":403,"headers":{"x-catbridge-blocked":"true"},"forms":[{"method":"get","action":"https://api.aurora.test/search","parameters":["q"]}]}}`))
	if e != nil || !strings.Contains(string(data), `"fetched":false`) || !strings.Contains(string(data), `"forms"`) || !strings.Contains(string(data), `"parameters":["q"]`) {
		t.Fatal(string(data), e)
	}
	job.Tool = "httpx"
	data, e = normalizeToolResult(job, []byte(`{"url":"https://api.aurora.test/","header":{"x_catbridge_blocked":"true"},"status_code":403}`))
	if e != nil || data != nil {
		t.Fatal("Synthetic service reported", string(data), e)
	}
}
func TestToolBatchDeterminism(t *testing.T) {
	job := brokerJob("https://api.aurora.test")
	job.Targets = []string{"https://b.aurora.test", "https://a.aurora.test"}
	a, _ := json.Marshal(toolBatches(job))
	job.Targets[0], job.Targets[1] = job.Targets[1], job.Targets[0]
	b, _ := json.Marshal(toolBatches(job))
	if string(a) != string(b) {
		t.Fatal("unstable")
	}
}
