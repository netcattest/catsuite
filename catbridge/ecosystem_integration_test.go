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

func TestLinuxEcosystemLaboratory(t *testing.T) {
	lockPath := os.Getenv("CATBRIDGE_ECOSYSTEM_LAB")
	if lockPath == "" {
		t.Skip("requires prepared Linux tools")
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
	name := "catsuite-ecosystem-lab-" + strings.ToLower(strings.NewReplacer("_", "a", "-", "b").Replace(randomCode()[:8]))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	if _, e = b.dockerOutput(ctx, "network", "create", "--internal", name); e != nil {
		t.Fatal(e)
	}
	directory := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "Aurora lab"}, DNSNames: []string{"aurora.test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	private, _ := x509.MarshalECPrivateKey(key)
	os.WriteFile(filepath.Join(directory, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644)
	os.WriteFile(filepath.Join(directory, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: private}), 0644)
	script, _ := os.ReadFile("runtime/ecosystem_lab.py")
	os.WriteFile(filepath.Join(directory, "lab.py"), script, 0644)
	lock, _ := os.ReadFile(lockPath)
	var doc map[string]any
	json.Unmarshal(lock, &doc)
	base := object(doc["preparation"])["base"].(string)
	if _, e = b.dockerOutput(ctx, "run", "-d", "--name", name, "--network", name, "--network-alias", "aurora.test", "--user", "65532:65532", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--memory=128m", "--pids-limit=32", "--mount", "type=bind,source="+directory+",target=/lab,readonly", base, "python", "/lab/lab.py"); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		end, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		b.dockerOutput(end, "rm", "-f", name)
		b.dockerOutput(end, "network", "rm", name)
	})
	address, _ := b.dockerOutput(ctx, "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name)
	b.runtimeNetwork = name
	b.upstreamCA = filepath.Join(directory, "cert.pem")
	b.scope = []string{"http://aurora.test:8080", "https://aurora.test:8443", "https://*.aurora.test:8443", strings.TrimSpace(string(address)), "https://203.0.113.10"}
	b.providerFixtures = map[string]string{"crt.sh": "http://aurora.test:8080", "api.certspotter.com": "http://aurora.test:8080", "web.archive.org": "http://aurora.test:8080", "internetdb.shodan.io": "http://aurora.test:8080"}
	b.dnsFixtures = map[string]map[string][]string{"aurora.test": {"A": {"203.0.113.10"}, "AAAA": {"2001:db8::1"}, "TXT": {"aurora-fixture"}}}
	tools := []string{"subfinder", "dnsx", "alterx", "uncover", "gau", "waybackurls", "ffuf", "arjun", "dalfox", "sqlmap", "jwt_tool", "gitleaks", "trufflehog", "semgrep", "naabu", "nmap", "testssl", "nikto", "amass"}
	for _, tool := range tools {
		t.Run(tool, func(t *testing.T) {
			input := validJob(b)
			input.ID = hash([]byte("ecosystem-" + tool))
			input.Tool = tool
			input.Capability = ecosystemTools[tool][0]
			input.Contract = 2
			input.Protection = "SECRET"
			input.TemplateIDs = nil
			input.ExpectedTemplates = nil
			input.ExpectedBinary = b.tools[tool].Binary
			input.ExpectedImage = b.tools[tool].Image
			input.ExpectedBroker = b.brokerImage.Image
			input.Scope = b.scope
			input.Timeout = 60
			input.Targets = []string{"https://aurora.test:8443/"}
			input.Parameters = &ToolParameters{Profile: "read-only", Methods: []string{"GET"}, Requests: 100, MaxResults: 100}
			p := input.Parameters
			if ecosystemExternal(input.Capability) {
				p.Profile = "external-approved"
				p.Providers = []string{"crtsh"}
				if input.Capability == "urls.history" {
					p.Providers = []string{"wayback"}
				}
				if input.Capability == "assets.search" {
					p.Providers = []string{"shodan-idb"}
					input.Targets = []string{"https://203.0.113.10"}
				}
			}
			if ecosystemActive(input.Capability) {
				p.Profile = "active-approved"
			}
			if tool == "dnsx" {
				p.RecordTypes = []string{"A", "AAAA", "TXT"}
			}
			if tool == "alterx" {
				p.Patterns = []string{"prefix"}
			}
			if ecosystemTCP(input.Capability) {
				p.Ports = []int{8443}
			}
			if tool == "nmap" {
				input.Capability = "net.services.fingerprint"
			}
			if tool == "arjun" {
				input.Targets = []string{"http://aurora.test:8080/parameters"}
			}
			if tool == "dalfox" || tool == "sqlmap" {
				input.Targets = []string{"http://aurora.test:8080/reflect?q=hello"}
				p.Parameter = "q"
				p.Requests = 200
				input.Timeout = 90
			}
			if tool == "nikto" {
				input.Targets = []string{"http://aurora.test:8080/"}
			}
			kind := ecosystemResource(input.Capability)
			if kind != "" {
				resource := EcosystemResource{Kind: kind}
				switch kind {
				case "wordlist":
					resource.Words = []string{"admin", "api/valid", "debug"}
				case "jwt":
					resource.Token = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"fictitious","exp":1800000000}`)) + ".c2ln"
				case "snapshot":
					data := []byte("import subprocess\napi_key = 'AKIAIOSFODNN7EXAMPLE'\neval(input())\n")
					resource.Files = []SnapshotFile{{Path: "example.py", Data: base64.StdEncoding.EncodeToString(data), SHA256: hash(data)}}
				}
				wire, _ := json.Marshal(resource)
				code, value := requestTest(t, c, "POST", s.URL+"/v2/resources", Resource{Flow: input.Flow, Revision: input.Revision, Protection: input.Protection, Kind: kind, SHA256: hash(wire), Bytes: len(wire), Chunks: 1})
				if code != 201 {
					t.Fatal(value)
				}
				input.Resource = value["id"].(string)
				if code, value = requestTest(t, c, "POST", s.URL+"/v2/resources/"+input.Resource+"/chunks/0", map[string]string{"data": base64.StdEncoding.EncodeToString(wire)}); code != 200 {
					t.Fatal(value)
				}
				if code, value = requestTest(t, c, "POST", s.URL+"/v2/resources/"+input.Resource+"/commit", map[string]any{}); code != 200 {
					t.Fatal(value)
				}
			}
			if e = b.validateTool(input); e != nil {
				t.Fatal(e)
			}
			results := []json.RawMessage{}
			taskCtx, end := context.WithTimeout(ctx, time.Duration(input.Timeout+15)*time.Second)
			defer end()
			e = b.executeTool(taskCtx, input, testID, func(result json.RawMessage) error { results = append(results, result); return nil })
			if e != nil {
				t.Fatalf("executor %s: %v", tool, e)
			}
			kinds := map[string]int{}
			for _, line := range results {
				var record map[string]any
				if json.Unmarshal(line, &record) != nil {
					t.Fatal("malformed result")
				}
				kinds[fmt.Sprint(record["kind"])]++
				if strings.Contains(string(line), "AKIAIOSFODNN7EXAMPLE") || strings.Contains(string(line), "private-subject") {
					t.Fatal("secret leaked")
				}
			}
			if len(results) == 0 {
				t.Fatal("no execution evidence")
			}
			if tool == "jwt_tool" && kinds["jwt"] != 1 || tool == "semgrep" && kinds["analysis"] == 0 || tool == "ffuf" && kinds["endpoint"] == 0 || tool == "dnsx" && kinds["dns"] == 0 || tool == "naabu" && kinds["service"] == 0 || tool == "nmap" && kinds["service"] == 0 {
				t.Fatal("missing typed result", kinds)
			}
			t.Log(tool, kinds)
		})
	}
}
