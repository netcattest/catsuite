package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
)

func TestEcosystemResourceBoundaries(t *testing.T) {
	valid := []byte(`{"kind":"wordlist","words":["admin","api/users"]}`)
	if _, e := ecosystemResourceDocument(valid, "wordlist"); e != nil {
		t.Fatal(e)
	}
	for _, data := range []string{string(valid) + `{}`, `{"kind":"wordlist","words":["../etc/passwd","admin"]}`, `{"kind":"wordlist","words":["admin","admin"]}`, `{"kind":"wordlist","words":["admin","api"],"shell":"whoami"}`} {
		if _, e := ecosystemResourceDocument([]byte(data), "wordlist"); e == nil {
			t.Fatal("unsafe resource accepted", data)
		}
	}
	code := []byte("eval(input())")
	snapshot := EcosystemResource{Kind: "snapshot", Files: []SnapshotFile{{Path: "src/main.py", Data: base64.StdEncoding.EncodeToString(code), SHA256: hash(code)}}}
	wire, _ := json.Marshal(snapshot)
	if _, e := ecosystemResourceDocument(wire, "snapshot"); e != nil {
		t.Fatal(e)
	}
	snapshot.Files[0].SHA256 = strings.Repeat("0", 64)
	wire, _ = json.Marshal(snapshot)
	if _, e := ecosystemResourceDocument(wire, "snapshot"); e == nil {
		t.Fatal("tampering accepted")
	}
	snapshot.Files[0].Path = "/etc/passwd"
	wire, _ = json.Marshal(snapshot)
	if _, e := ecosystemResourceDocument(wire, "snapshot"); e == nil {
		t.Fatal("host path accepted")
	}
}
func TestEcosystemProvidersAndScope(t *testing.T) {
	job := brokerJob("https://example.com/")
	job.Tool = "subfinder"
	job.Capability = "assets.subdomains.discover"
	job.Parameters.Providers = []string{"crtsh"}
	broker, e := newHTTPBroker(BrokerPolicy{Job: job, HostScope: job.Scope})
	if e != nil {
		t.Fatal(e)
	}
	for address, expected := range map[string]bool{"https://crt.sh/?q=%25.example.com&output=json": true, "https://crt.sh/?q=%25.other.com&output=json": false, "https://crt.sh/?q=%25.example.com&output=json&command=whoami": false, "https://api.certspotter.com/v1/issuances?domain=example.com": false, "https://crt.sh:8443/?q=example.com&output=json": false} {
		u, _ := url.Parse(address)
		if broker.providerRequest(u, "GET") != expected {
			t.Fatal(address)
		}
	}
	if broker.providerRequest(mustURL("https://crt.sh/?q=example.com&output=json"), "POST") {
		t.Fatal("provider mutation allowed")
	}
	job.Capability = "code.sast.scan"
	job.Tool = "semgrep"
	broker, e = newHTTPBroker(BrokerPolicy{Job: job, HostScope: job.Scope})
	if e != nil {
		t.Fatal(e)
	}
	if broker.permits(mustURL(job.Targets[0]), "GET") {
		t.Fatal("offline network allowed")
	}
	job.Capability = "web.xss.analyze"
	job.Tool = "dalfox"
	job.Targets = []string{"https://example.com/profile?q=hello&account=1"}
	job.Parameters.Parameter = "q"
	broker, e = newHTTPBroker(BrokerPolicy{Job: job, HostScope: job.Scope})
	if e != nil {
		t.Fatal(e)
	}
	if !broker.permits(mustURL("https://example.com/profile?q=test&account=1"), "GET") || broker.permits(mustURL("https://example.com/profile?q=test&account=2"), "GET") || broker.permits(mustURL("https://example.com/admin?q=test&account=1"), "GET") {
		t.Fatal("query scope escaped")
	}
}
func TestEcosystemHeadersSecretProtection(t *testing.T) {
	input := brokerJob("https://example.com")
	input.Capability = "web.xss.analyze"
	input.Headers = []SharedHeader{{Name: "Authorization", Value: "Bearer test-only"}}
	input.DataProfile = "selected-headers"
	if validateEcosystemHeaders(input) == nil {
		t.Fatal("public credential accepted")
	}
	input.Protection = "SECRET"
	if e := validateEcosystemHeaders(input); e != nil {
		t.Fatal(e)
	}
	input.Headers[0].Name = "Host"
	if validateEcosystemHeaders(input) == nil {
		t.Fatal("host header accepted")
	}
	input.Headers[0].Name = "Authorization"
	input.Capability = "urls.history"
	if validateEcosystemHeaders(input) == nil {
		t.Fatal("credential sent to external provider")
	}
}
func TestEcosystemOutputsDoNotExposeSecrets(t *testing.T) {
	job := brokerJob("https://example.com")
	job.Tool = "trufflehog"
	record, e := normalizeEcosystemResult(job, map[string]any{"DetectorName": "Test", "Raw": "private-secret", "RawV2": "private-secret", "SourceMetadata": map[string]any{"Data": map[string]any{"Filesystem": map[string]any{"file": "/tmp/snapshot/config.py", "line": 2}}}}, nil)
	if e != nil {
		t.Fatal(e)
	}
	wire, _ := json.Marshal(record)
	if strings.Contains(string(wire), "private-secret") || record["path"] != "config.py" {
		t.Fatal(string(wire))
	}
	token := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"private-subject","exp":1800000000}`)) + ".c2ln"
	record, e = jwtSummary(token)
	if e != nil {
		t.Fatal(e)
	}
	wire, _ = json.Marshal(record)
	if strings.Contains(string(wire), "private-subject") || record["signatureVerified"] != false {
		t.Fatal(string(wire))
	}
}
func TestEcosystemTCPUnauthorizedHasNoEffect(t *testing.T) {
	job := brokerJob("https://example.com")
	job.Tool = "nmap"
	job.Capability = "net.ports.discover"
	job.Parameters.Ports = []int{443}
	broker, e := newHTTPBroker(BrokerPolicy{Job: job, HostScope: job.Scope})
	if e != nil {
		t.Fatal(e)
	}
	for _, path := range []string{"/_catsuite/tcp?port=22", "/_catsuite/tcp?port=443&host=other.com"} {
		req := httptest.NewRequest("GET", "http://catbridge.internal"+path, nil)
		req.URL.Scheme = ""
		req.URL.Host = ""
		req.Host = "catbridge.internal"
		reply := httptest.NewRecorder()
		broker.ServeHTTP(reply, req)
		if reply.Code != http.StatusForbidden || broker.requests != 0 {
			t.Fatal(reply.Code, broker.requests)
		}
	}
}

func TestEcosystemAnalysisDoesNotInventFindings(t *testing.T) {
	job := brokerJob("https://example.com/profile?id=1")
	job.Tool = "sqlmap"
	job.Parameters.Parameter = "id"
	count := 0
	emit := func(record map[string]any) error {
		if record != nil {
			count++
		}
		return nil
	}
	for _, data := range []string{"[]", "Target URL,Place,Parameter,Technique(s),Note(s)\n", "Target URL,Place,Parameter,Technique(s),Note(s)\nhttps://example.com,GET,id,,\n"} {
		if e := emitEcosystemResults(job, []byte(data), "sqlmap", nil, emit); e != nil {
			t.Fatal(e)
		}
	}
	if count != 0 {
		t.Fatal("empty SQL report became finding")
	}
	if e := emitEcosystemResults(job, []byte("Target URL,Place,Parameter,Technique(s),Note(s)\nhttps://example.com,GET,id,B,\n"), "sqlmap", nil, emit); e != nil || count != 1 {
		t.Fatal(e, count)
	}
	job.Tool = "dalfox"
	if record, e := normalizeEcosystemResult(job, map[string]any{"meta": map[string]any{"findings_count": 0}}, nil); e != nil || record != nil {
		t.Fatal("summary became finding")
	}
	job.Tool = "nikto"
	count = 0
	if e := emitEcosystemResults(job, []byte(`[{"host":"example.com","vulnerabilities":[{"id":"1","msg":"Observed configuration"}]}]`), "json", nil, emit); e != nil || count != 1 {
		t.Fatal(e, count)
	}
}
func TestEcosystemStaticCommandCapabilities(t *testing.T) {
	job := brokerJob("https://example.com/profile?id=1")
	job.Parameters.Parameter = "id"
	job.Parameters.MaxResults = 100
	job.Parameters.Providers = []string{"crtsh"}
	job.Parameters.Patterns = []string{"prefix"}
	job.Parameters.RecordTypes = []string{"A"}
	job.Parameters.Ports = []int{443}
	job.Timeout = 60
	job.Rate = 5
	for tool, caps := range ecosystemTools {
		for _, capability := range caps {
			job.Tool = tool
			job.Capability = capability
			command, e := ecosystemCommandFor(job, job.Targets[0], "http://127.0.0.1:8123", EcosystemResource{Token: "test"}, map[int]int{12345: 443})
			if e != nil {
				t.Fatal(tool, e)
			}
			for _, arg := range command.Args {
				if arg == "--os-shell" || arg == "--os-pwn" || arg == "--headless" || arg == "--script" || arg == "--verify" {
					t.Fatal(tool, arg)
				}
			}
			if command.Entry != ecosystemEntry(tool) {
				t.Fatal(tool)
			}
			for path := range command.Files {
				if !slices.Contains([]string{"/tmp/hosts.txt", "/tmp/prefix.txt", "/tmp/words.txt", "/tmp/sqlmap-targets.txt", "/tmp/gitleaks.toml"}, path) {
					t.Fatal("uncontrolled temporary path", tool, path)
				}
			}
		}
	}
	if ecosystemUnique([]string{"A", "B", "A"}) {
		t.Fatal("duplicate non-adjacent values")
	}
}
