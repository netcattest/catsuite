package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLinuxCapabilitiesLaboratory(t *testing.T) {
	lockPath := os.Getenv("CATBRIDGE_LINUX_LAB")
	if lockPath == "" {
		t.Skip("Linux container integration requires CATBRIDGE_LINUX_LAB")
	}
	b, s, c := setupBridge(t)
	c = pairedClient(t, b, s, c)
	fingerprint, e := os.ReadFile(filepath.Join(filepath.Dir(lockPath), "author.sha256"))
	if e != nil {
		t.Fatal(e)
	}
	if e = b.loadToolLock(lockPath, strings.TrimSpace(string(fingerprint))); e != nil || b.runtimeError != "" {
		t.Fatal(e, b.runtimeError)
	}
	name := "catsuite-lab-" + randomCode()[:8]
	name = strings.ToLower(strings.NewReplacer("_", "a", "-", "b").Replace(name))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if _, e = b.dockerOutput(ctx, "network", "create", "--internal", name); e != nil {
		t.Fatal(e)
	}
	labDir := t.TempDir()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "Aurora lab"}, DNSNames: []string{"aurora.test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, cert, cert, &caKey.PublicKey, caKey)
	key, _ := x509.MarshalECPrivateKey(caKey)
	os.WriteFile(filepath.Join(labDir, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644)
	os.WriteFile(filepath.Join(labDir, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: key}), 0644)
	script, e := os.ReadFile("runtime/lab.py")
	if e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(labDir, "lab.py"), script, 0644)
	data, e := os.ReadFile(lockPath)
	if e != nil {
		t.Fatal(e)
	}
	var doc map[string]any
	json.Unmarshal(data, &doc)
	base := doc["preparation"].(map[string]any)["base"].(string)
	if _, e = b.dockerOutput(ctx, "run", "-d", "--name", name, "--network", name, "--network-alias", "aurora.test", "--user", "65532:65532", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--memory=128m", "--pids-limit=32", "--mount", "type=bind,source="+labDir+",target=/lab,readonly", base, "python", "/lab/lab.py"); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		end, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		b.dockerOutput(end, "rm", "-f", name)
		b.dockerOutput(end, "network", "rm", name)
	})
	ip, e := b.dockerOutput(ctx, "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name)
	if e != nil {
		t.Fatal(e)
	}
	b.runtimeNetwork = name
	b.upstreamCA = filepath.Join(labDir, "cert.pem")
	b.scope = []string{"http://aurora.test:8080", "https://aurora.test:8443", strings.TrimSpace(string(ip))}
	for _, tool := range []string{"httpx", "katana", "schemathesis"} {
		t.Run(tool, func(t *testing.T) {
			input := validJob(b)
			input.ID = hash([]byte(tool))
			input.Protection = "PUBLIC"
			input.Tool = tool
			input.Capability = toolCapabilities[tool]
			input.TemplateIDs = nil
			input.ExpectedTemplates = nil
			input.Contract = 1
			input.ExpectedBinary = b.tools[tool].Binary
			input.ExpectedImage = b.tools[tool].Image
			input.ExpectedBroker = b.brokerImage.Image
			input.Scope = b.scope
			input.Timeout = 120
			input.Targets = []string{"https://aurora.test:8443/"}
			input.Parameters = &ToolParameters{Profile: "read-only", Methods: []string{"GET"}, Requests: 30}
			if tool == "katana" {
				input.Parameters.Depth = 2
				input.Parameters.Pages = 10
			}
			if tool == "schemathesis" {
				input.Timeout = 300
				input.Parameters.Examples = 5
				input.Parameters.Seed = 7
				input.Parameters.Operations = []string{"GET /api/valid", "GET /api/broken", "GET /api/crash"}
				input.Parameters.Paths = []string{"/api/valid", "/api/broken", "/api/crash"}
				schema, readError := os.ReadFile("runtime/openapi.json")
				if readError != nil {
					t.Fatal(readError)
				}
				code, value := requestTest(t, c, "POST", s.URL+"/v2/resources", Resource{Flow: input.Flow, Revision: input.Revision, Protection: input.Protection, SHA256: hash(schema), Bytes: len(schema), Chunks: 1})
				if code != 201 {
					t.Fatal(value)
				}
				input.Resource = value["id"].(string)
				code, value = requestTest(t, c, "POST", s.URL+"/v2/resources/"+input.Resource+"/chunks/0", map[string]string{"data": base64.StdEncoding.EncodeToString(schema)})
				if code != 200 {
					t.Fatal(value)
				}
				code, value = requestTest(t, c, "POST", s.URL+"/v2/resources/"+input.Resource+"/commit", map[string]any{})
				if code != 200 {
					t.Fatal(value)
				}
			}
			code, value := requestTest(t, c, "POST", s.URL+"/v2/jobs", input)
			if code != 202 {
				t.Fatal(value)
			}
			until := time.Now().Add(330 * time.Second)
			var job Job
			for time.Now().Before(until) {
				b.mu.Lock()
				job = *b.jobs[input.ID]
				b.mu.Unlock()
				if job.Status != "running" {
					break
				}
				time.Sleep(250 * time.Millisecond)
			}
			if job.Status != "complete" {
				t.Fatalf("%s: %s %+v", job.Status, job.Error, job.Batches)
			}
			if len(job.Results) < 2 {
				t.Fatal("No tool result", job.Results)
			}
			kinds := map[string]int{}
			violations := 0
			jsFound := false
			formsFound := false
			tlsObserved := false
			for _, line := range job.Results {
				var result map[string]any
				json.Unmarshal(line, &result)
				kinds[result["kind"].(string)]++
				if forms, ok := result["forms"].([]any); ok && len(forms) > 0 {
					formsFound = true
				}
				if result["kind"] == "api_test" {
					if result["tested"].(float64) <= 0 {
						t.Fatal("No requests reached origin", result)
					}
					violations += len(result["failures"].([]any))
				}
				if strings.HasSuffix(fmt.Sprint(result["url"]), "/api/undocumented") && strings.Contains(fmt.Sprint(result["source"]), "app.js") {
					jsFound = true
				}
				if result["kind"] == "broker_summary" {
					for _, fingerprint := range object(result["upstreamTLS"]) {
						if fingerprint == hash(der) {
							tlsObserved = true
						}
					}
				}
			}
			if tool == "httpx" && kinds["http_service"] == 0 || tool == "katana" && kinds["endpoint"] == 0 || tool == "schemathesis" && kinds["api_test"] == 0 {
				t.Fatal(kinds)
			}
			if !tlsObserved {
				t.Fatal("Missing upstream TLS identity")
			}
			if tool == "katana" && (!jsFound || !formsFound) {
				t.Fatal("JavaScript endpoint provenance missing", job.Results)
			}
			if tool == "schemathesis" && violations < 2 {
				t.Fatal("Expected schema and 5xx violations", job.Results)
			}
			if tool == "schemathesis" {
				reproduced, e := b.dockerOutput(ctx, "exec", name, "python", "-c", "import json,urllib.request; data=json.load(urllib.request.urlopen('http://127.0.0.1:8080/api/broken')); assert isinstance(data['id'],str); print('observed-type-mismatch')")
				if e != nil || strings.TrimSpace(string(reproduced)) != "observed-type-mismatch" {
					t.Fatal("Manual case reproduction failed", e)
				}
			}
			t.Log(tool, kinds, "requests reserved", job.RequestsReserved)
			code, value = requestTest(t, c, "GET", s.URL+"/v2/jobs/"+input.ID+"/results?cursor=0", nil)
			if code != 200 || value["total"].(float64) != float64(len(job.Results)) {
				t.Fatal(value)
			}
		})
	}
}
