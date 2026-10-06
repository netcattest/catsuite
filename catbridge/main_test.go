package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var testKeys = map[*http.Client]*ecdsa.PrivateKey{}

const testID = "12345678-1234-4234-8234-123456789012"

func TestSelectedHeadersRequireExplicitProfileAndSafeFraming(t *testing.T) {
	b, _, _ := setupBridge(t)
	input := validJob(b)
	input.Headers = []SharedHeader{{Name: "Authorization", Value: "Bearer fictional-selected-token"}}
	if _, e := b.validateJob(input); e == nil {
		t.Fatal("Headers without explicit profile")
	}
	input.DataProfile = "selected-headers"
	if _, e := b.validateJob(input); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"Host", "Content-Length", "Transfer-Encoding", "Proxy-Authorization"} {
		input.Headers = []SharedHeader{{Name: name, Value: "fictional"}}
		if _, e := b.validateJob(input); e == nil {
			t.Fatal(name)
		}
	}
	input.Headers = []SharedHeader{{Name: "Cookie", Value: "first\r\nHost: other.test"}}
	if _, e := b.validateJob(input); e == nil {
		t.Fatal("Header injection")
	}
	input.Headers = []SharedHeader{{Name: "Cookie", Value: "first"}, {Name: "cookie", Value: "second"}}
	if _, e := b.validateJob(input); e == nil {
		t.Fatal("Duplicate header")
	}
}

const templateYAML = "id: cache-policy\ninfo:\n  name: Cache policy\n  author: CatSuite\n  severity: info\nhttp:\n  - method: GET\n    path:\n      - '{{BaseURL}}/api/perfil'\n    matchers:\n      - type: word\n        part: header\n        words: [public]\n"

func setupBridge(t *testing.T) (*Bridge, *httptest.Server, *http.Client) {
	t.Helper()
	dir := t.TempDir()
	ca, key, server, e := identity(dir, "https://127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	binary := filepath.Join(dir, "nuclei-fixture")
	if e = os.WriteFile(binary, []byte("fixture"), 0600); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "reviewed.yaml")
	if e = os.WriteFile(path, []byte(templateYAML), 0600); e != nil {
		t.Fatal(e)
	}
	b := &Bridge{directory: dir, ca: ca, caKey: key, serverCertificate: server, scope: []string{"api.aurora.test"}, binary: binary, binaryHash: hash([]byte("fixture")), version: "v3.test", templates: map[string]Template{"cache-policy": {ID: "cache-policy", Path: path, SHA256: hash([]byte(templateYAML)), Name: map[string]string{"pt-BR": "Cache", "en": "Cache"}}}, jobs: map[string]*Job{}, slots: make(chan struct{}, 2)}
	b.execute = func(ctx context.Context, in JobRequest, templates []Template, emit func(json.RawMessage) error) error {
		return emit(json.RawMessage(`{"matched-at":"https://api.aurora.test/api/perfil","request":"private","response":"private","curl-command":"private","template-id":"cache-policy"}`))
	}
	serverTest := httptest.NewUnstartedServer(b.handler())
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	serverTest.TLS = &tls.Config{Certificates: []tls.Certificate{server}, ClientAuth: tls.RequestClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS12}
	serverTest.StartTLS()
	t.Cleanup(serverTest.Close)
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	t.Cleanup(func() { client.CloseIdleConnections() })
	return b, serverTest, client
}
func requestTest(t *testing.T, client *http.Client, method, url string, data any) (int, map[string]any) {
	t.Helper()
	if input, ok := data.(JobRequest); ok && strings.HasSuffix(url, "/v2/jobs") && input.Authorization == "" {
		code, grant := requestTest(t, client, "POST", strings.TrimSuffix(url, "/jobs")+"/authorizations", input)
		if code == 200 {
			input.Authorization = grant["authorization"].(string)
			data = input
		}
	}
	var buf bytes.Buffer
	if data != nil {
		if e := json.NewEncoder(&buf).Encode(data); e != nil {
			t.Fatal(e)
		}
	}
	req, e := http.NewRequest(method, url, &buf)
	if e != nil {
		t.Fatal(e)
	}
	if key := testKeys[client]; key != nil {
		if e = signMessage(req.Header, req, 0, buf.Bytes(), testID, key, time.Now()); e != nil {
			t.Fatal(e)
		}
	}
	res, e := client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	defer res.Body.Close()
	wire, e := io.ReadAll(res.Body)
	if e != nil {
		t.Fatal(e)
	}
	key := res.TLS.PeerCertificates[0].PublicKey.(*ecdsa.PublicKey)
	if _, _, e = verifyMessage(res.Header, req, res.StatusCode, wire, hash(res.TLS.PeerCertificates[0].Raw), key, time.Now()); e != nil {
		t.Fatal(e)
	}
	var result map[string]any
	if e = json.Unmarshal(wire, &result); e != nil {
		t.Fatal(e)
	}
	return res.StatusCode, result
}
func pairedClient(t *testing.T, b *Bridge, s *httptest.Server, c *http.Client) *http.Client {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: testID}}, key)
	if e != nil {
		t.Fatal(e)
	}
	testKeys[c] = key
	pairing := Pairing{Protocol: 2, Code: randomCode(), Expires: time.Now().Add(time.Minute).UnixMilli()}
	if e = writeJSON(filepath.Join(b.directory, "pairing.json"), pairing); e != nil {
		t.Fatal(e)
	}
	status, result := requestTest(t, c, "POST", s.URL+"/v2/pair", map[string]any{"id": testID, "code": pairing.Code, "csr": base64.StdEncoding.EncodeToString(csr)})
	if status != 200 {
		t.Fatal(result)
	}
	keyBytes, _ := x509.MarshalECPrivateKey(key)
	cert, e := tls.X509KeyPair([]byte(result["certificate"].(string)), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}))
	if e != nil {
		t.Fatal(e)
	}
	config := c.Transport.(*http.Transport).TLSClientConfig.Clone()
	config.Certificates = []tls.Certificate{cert}
	next := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: config}}
	testKeys[next] = key
	t.Cleanup(next.CloseIdleConnections)
	return next
}
func validJob(b *Bridge) JobRequest {
	return JobRequest{Capability: "nuclei.scan", Flow: testID, Revision: strings.Repeat("c", 64), Node: "scan", Protection: "SECRET", ID: strings.Repeat("a", 64), Tool: "nuclei", Targets: []string{"https://api.aurora.test/api/perfil"}, TemplateIDs: []string{"cache-policy"}, Scope: b.scope, Rate: 5, Timeout: 10, Lease: 15, Approval: strings.Repeat("b", 64), DataProfile: "endpoints-only", ExpectedBinary: b.binaryHash, ExpectedTemplates: map[string]string{"cache-policy": b.templates["cache-policy"].SHA256}}
}
func waitJob(t *testing.T, b *Bridge, id string) *Job {
	t.Helper()
	until := time.Now().Add(3 * time.Second)
	for time.Now().Before(until) {
		b.mu.Lock()
		job := b.jobs[id]
		if job != nil && job.Status != "running" && job.Status != "pausing" {
			copy := *job
			b.mu.Unlock()
			return &copy
		}
		b.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("job did not end")
	return nil
}
func TestTLSPairingAndRevocation(t *testing.T) {
	b, s, c := setupBridge(t)
	status, _ := requestTest(t, c, "GET", s.URL+"/v2/capabilities", nil)
	if status != 403 {
		t.Fatal(status)
	}
	paired := pairedClient(t, b, s, c)
	status, result := requestTest(t, paired, "GET", s.URL+"/v2/capabilities", nil)
	if status != 200 || result["protocol"] != float64(2) {
		t.Fatal(result)
	}
	status, _ = requestTest(t, paired, "POST", s.URL+"/v2/revoke", map[string]string{"id": testID})
	if status != 200 {
		t.Fatal(status)
	}
	status, _ = requestTest(t, paired, "GET", s.URL+"/v2/capabilities", nil)
	if status != 403 {
		t.Fatal(status)
	}
}
func TestTLSRejectsForeignAuthority(t *testing.T) {
	_, s, c := setupBridge(t)
	config := c.Transport.(*http.Transport).TLSClientConfig.Clone()
	config.RootCAs = x509.NewCertPool()
	bad := &http.Client{Timeout: time.Second, Transport: &http.Transport{TLSClientConfig: config}}
	defer bad.CloseIdleConnections()
	if res, e := bad.Get(s.URL + "/v2/capabilities"); e == nil {
		res.Body.Close()
		t.Fatal("foreign authority accepted")
	}
}
func TestPairingExpiryAndSingleUse(t *testing.T) {
	b, s, c := setupBridge(t)
	pairedClient(t, b, s, c)
	var pair Pairing
	readJSON(filepath.Join(b.directory, "pairing.json"), &pair)
	if pair.Code != "" || pair.Expires != 0 {
		t.Fatal("pairing still reusable")
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: testID}}, key)
	testKeys[c] = key
	pair = Pairing{Protocol: 2, Code: randomCode(), Expires: time.Now().Add(-time.Second).UnixMilli()}
	writeJSON(filepath.Join(b.directory, "pairing.json"), pair)
	status, _ := requestTest(t, c, "POST", s.URL+"/v2/pair", map[string]string{"id": testID, "code": pair.Code, "csr": base64.StdEncoding.EncodeToString(csr)})
	if status != 403 {
		t.Fatal(status)
	}
}
func TestScopes(t *testing.T) {
	for _, u := range []string{"https://evilapi.aurora.test/x", "https://api.aurora.test.evil/x", "https://user@api.aurora.test/x", "file:///private", "https://api.aurora.test/x#fragment"} {
		if allows([]string{"api.aurora.test"}, u) {
			t.Fatal(u)
		}
	}
	if !allows([]string{"*.aurora.test:443"}, "https://api.aurora.test/x") || allows([]string{"*.aurora.test:443"}, "http://api.aurora.test/x") {
		t.Fatal("scope mismatch")
	}
}
func TestJobLimitsAndHashes(t *testing.T) {
	b, _, _ := setupBridge(t)
	for _, mutation := range []func(*JobRequest){func(j *JobRequest) { j.Rate = 6 }, func(j *JobRequest) { j.Timeout = 601 }, func(j *JobRequest) { j.Lease = 30 }, func(j *JobRequest) { j.ExpectedBinary = "changed" }, func(j *JobRequest) { j.Targets = []string{"https://outside.test"} }, func(j *JobRequest) { j.ExpectedTemplates = map[string]string{} }, func(j *JobRequest) { j.DataProfile = "everything" }} {
		job := validJob(b)
		mutation(&job)
		if _, e := b.validateJob(job); e == nil {
			t.Fatal("invalid job accepted")
		}
	}
}
func TestTemplatesRejectPowerfulModes(t *testing.T) {
	b, _, _ := setupBridge(t)
	for _, text := range []string{templateYAML + "code: []\n", strings.Replace(templateYAML, "method: GET", "method: POST", 1), strings.Replace(templateYAML, "{{BaseURL}}/api/perfil", "https://outside.test", 1), strings.Replace(templateYAML, "    matchers:", "    redirects: true\n    matchers:", 1), templateYAML + "---\nhttp: []\n"} {
		tpl := b.templates["cache-policy"]
		os.WriteFile(tpl.Path, []byte(text), 0600)
		tpl.SHA256 = hash([]byte(text))
		if validateTemplate(tpl) == nil {
			t.Fatal("unsafe template accepted")
		}
	}
}
func TestTemplateTampering(t *testing.T) {
	b, _, _ := setupBridge(t)
	tpl := b.templates["cache-policy"]
	os.WriteFile(tpl.Path, []byte(templateYAML+"\n"), 0600)
	if validateTemplate(tpl) == nil {
		t.Fatal("tampered template accepted")
	}
}
func TestIdempotencyAndRedaction(t *testing.T) {
	b, s, c := setupBridge(t)
	paired := pairedClient(t, b, s, c)
	var executions atomic.Int32
	original := b.execute
	b.execute = func(ctx context.Context, j JobRequest, t []Template, e func(json.RawMessage) error) error {
		executions.Add(1)
		return original(ctx, j, t, e)
	}
	job := validJob(b)
	status, _ := requestTest(t, paired, "POST", s.URL+"/v2/jobs", job)
	if status != 202 {
		t.Fatal(status)
	}
	result := waitJob(t, b, job.ID)
	if result.Status != "complete" || len(result.Results) != 1 || strings.Contains(string(result.Results[0]), "private") {
		t.Fatal(result)
	}
	status, _ = requestTest(t, paired, "POST", s.URL+"/v2/jobs", job)
	if status != 200 || executions.Load() != 1 {
		t.Fatal("repeated execution")
	}
	job.Timeout = 11
	status, _ = requestTest(t, paired, "POST", s.URL+"/v2/jobs", job)
	if status != 409 {
		t.Fatal(status)
	}
}
func TestCancellation(t *testing.T) {
	b, s, c := setupBridge(t)
	paired := pairedClient(t, b, s, c)
	b.execute = func(ctx context.Context, j JobRequest, t []Template, e func(json.RawMessage) error) error {
		<-ctx.Done()
		return ctx.Err()
	}
	j := validJob(b)
	requestTest(t, paired, "POST", s.URL+"/v2/jobs", j)
	status, _ := requestTest(t, paired, "POST", s.URL+"/v2/jobs/"+j.ID+"/cancel", nil)
	if status != 200 || waitJob(t, b, j.ID).Status != "cancelled" {
		t.Fatal("cancel failed")
	}
}
func TestLeaseExpiry(t *testing.T) {
	b, s, c := setupBridge(t)
	paired := pairedClient(t, b, s, c)
	b.execute = func(ctx context.Context, j JobRequest, t []Template, e func(json.RawMessage) error) error {
		<-ctx.Done()
		return ctx.Err()
	}
	j := validJob(b)
	requestTest(t, paired, "POST", s.URL+"/v2/jobs", j)
	b.mu.Lock()
	b.jobs[j.ID].lease = time.Now().Add(-time.Second)
	b.mu.Unlock()
	if waitJob(t, b, j.ID).Status != "paused" {
		t.Fatal("lease failed")
	}
}
func TestMalformedAndOutOfScopeResults(t *testing.T) {
	for _, result := range []string{"garbage", `{"matched-at":"https://outside.test"}`, strings.Repeat("a", 128*1024+1)} {
		t.Run(fmt.Sprint(len(result)), func(t *testing.T) {
			b, s, c := setupBridge(t)
			paired := pairedClient(t, b, s, c)
			b.execute = func(ctx context.Context, j JobRequest, t []Template, e func(json.RawMessage) error) error {
				return e(json.RawMessage(result))
			}
			j := validJob(b)
			requestTest(t, paired, "POST", s.URL+"/v2/jobs", j)
			if waitJob(t, b, j.ID).Status != "error" {
				t.Fatal("invalid result accepted")
			}
		})
	}
}
func TestConcurrentLimit(t *testing.T) {
	b, s, c := setupBridge(t)
	paired := pairedClient(t, b, s, c)
	b.execute = func(ctx context.Context, j JobRequest, t []Template, e func(json.RawMessage) error) error {
		<-ctx.Done()
		return ctx.Err()
	}
	for i := 0; i < 3; i++ {
		j := validJob(b)
		j.ID = hash([]byte(fmt.Sprint(i)))
		status, _ := requestTest(t, paired, "POST", s.URL+"/v2/jobs", j)
		if i < 2 && status != 202 || i == 2 && status != 429 {
			t.Fatal(status)
		}
	}
	b.mu.Lock()
	ids := make([]string, 0, len(b.jobs))
	for id, j := range b.jobs {
		j.cancel()
		ids = append(ids, id)
	}
	b.mu.Unlock()
	for _, id := range ids {
		waitJob(t, b, id)
	}
}
func TestInterruptedJobsNeverRepeat(t *testing.T) {
	b, _, _ := setupBridge(t)
	j := &Job{ID: strings.Repeat("c", 64), Owner: testID, Digest: strings.Repeat("d", 64), Status: "running", Results: []json.RawMessage{}}
	if e := b.persistJob(j); e != nil {
		t.Fatal(e)
	}
	if e := b.restoreJobs(); e != nil {
		t.Fatal(e)
	}
	if b.jobs[j.ID].Status != "interrupted" || b.jobs[j.ID].Error != "E_UNKNOWN_RESULT" {
		t.Fatal("unknown send resumed")
	}
}
func TestDecodeRejectsUnapprovedData(t *testing.T) {
	b, s, c := setupBridge(t)
	paired := pairedClient(t, b, s, c)
	job := validJob(b)
	data, _ := json.Marshal(job)
	var fields map[string]any
	json.Unmarshal(data, &fields)
	fields["headers"] = map[string]string{"Authorization": "private"}
	status, _ := requestTest(t, paired, "POST", s.URL+"/v2/jobs", fields)
	if status != 400 {
		t.Fatal(status)
	}
}
