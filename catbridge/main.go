package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

type Template struct {
	ID     string            `json:"id"`
	Path   string            `json:"path"`
	SHA256 string            `json:"sha256"`
	Name   map[string]string `json:"name"`
}
type Device struct {
	Serial  string `json:"serial"`
	Revoked bool   `json:"revoked"`
}
type State struct {
	Devices map[string]Device `json:"devices"`
}
type Pairing struct {
	Protocol    int    `json:"protocol"`
	URL         string `json:"url"`
	Fingerprint string `json:"fingerprint"`
	Code        string `json:"code"`
	Expires     int64  `json:"expires"`
	Name        string `json:"name"`
	Failures    int    `json:"failures,omitempty"`
}
type SharedHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type JobRequest struct {
	Contract          int               `json:"contractVersion,omitempty"`
	ExpectedImage     string            `json:"expectedImage,omitempty"`
	ExpectedBroker    string            `json:"expectedBroker,omitempty"`
	Resource          string            `json:"resource,omitempty"`
	Parameters        *ToolParameters   `json:"parameters,omitempty"`
	RetryUnknown      bool              `json:"retryUnknown,omitempty"`
	Capability        string            `json:"capability"`
	Flow              string            `json:"flow"`
	Revision          string            `json:"revision"`
	Node              string            `json:"node"`
	Protection        string            `json:"protection"`
	Authorization     string            `json:"authorization,omitempty"`
	Headers           []SharedHeader    `json:"headers,omitempty"`
	ID                string            `json:"id"`
	Tool              string            `json:"tool"`
	Targets           []string          `json:"targets"`
	TemplateIDs       []string          `json:"templateIds"`
	Scope             []string          `json:"scope"`
	Rate              int               `json:"rate"`
	Timeout           int               `json:"timeout"`
	Lease             int               `json:"lease"`
	Approval          string            `json:"approval"`
	DataProfile       string            `json:"dataProfile"`
	ExpectedBinary    string            `json:"expectedBinary"`
	ExpectedTemplates map[string]string `json:"expectedTemplates"`
}
type Job struct {
	Resource         string  `json:"resource,omitempty"`
	RequestsReserved int     `json:"requestsReserved,omitempty"`
	PagesReserved    int     `json:"pagesReserved,omitempty"`
	Flow             string  `json:"flow"`
	Revision         string  `json:"revision"`
	Node             string  `json:"node"`
	Capability       string  `json:"capability"`
	Protection       string  `json:"protection"`
	DefinitionHash   string  `json:"definitionHash"`
	Batches          []Batch `json:"batches"`
	Spent            int64   `json:"spentMillis"`
	pauseRequested   bool
	ID               string            `json:"id"`
	Owner            string            `json:"-"`
	Digest           string            `json:"-"`
	Status           string            `json:"status"`
	Error            string            `json:"error,omitempty"`
	Results          []json.RawMessage `json:"results"`
	Started          int64             `json:"started"`
	Finished         int64             `json:"finished,omitempty"`
	Binary           map[string]string `json:"binary"`
	Templates        map[string]string `json:"templates"`
	lease            time.Time
	cancel           context.CancelFunc
}
type Bridge struct {
	pairWindows       map[string]pairWindow
	pairChallenges    map[string]int64
	tools             map[string]ToolImage
	brokerImage       ToolImage
	docker            string
	dockerHost        string
	runtimeError      string
	runtimeNetwork    string
	upstreamCA        string
	providerFixtures  map[string]string
	dnsFixtures       map[string]map[string][]string
	replay            replayJournal
	mu                sync.Mutex
	directory         string
	publicURL         string
	ca                *x509.Certificate
	caKey             *ecdsa.PrivateKey
	serverCertificate tls.Certificate
	scope             []string
	templates         map[string]Template
	binary            string
	binaryHash        string
	version           string
	jobs              map[string]*Job
	slots             chan struct{}
	execute           func(context.Context, JobRequest, []Template, func(json.RawMessage) error) error
}

var errPermission = errors.New("E_PERMISSION")
var idPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var templatePattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,80}$`)

func randomCode() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func serial() *big.Int {
	n, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		panic(e)
	}
	return n
}
func hash(b []byte) string { value := sha256.Sum256(b); return hex.EncodeToString(value[:]) }
func writeJSON(path string, value any) error {
	bytes, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".catbridge-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(bytes)
	}
	if e == nil {
		e = f.Sync()
	}
	closeError := f.Close()
	if e != nil {
		return e
	}
	if closeError != nil {
		return closeError
	}
	return os.Rename(name, path)
}
func readJSON(path string, value any) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return json.NewDecoder(io.LimitReader(f, 1024*1024)).Decode(value)
}
func (b *Bridge) state() (State, error) {
	s := State{Devices: map[string]Device{}}
	e := readJSON(filepath.Join(b.directory, "devices.json"), &s)
	if os.IsNotExist(e) {
		e = nil
	}
	if s.Devices == nil {
		s.Devices = map[string]Device{}
	}
	return s, e
}
func identity(directory, publicURL string) (*x509.Certificate, *ecdsa.PrivateKey, tls.Certificate, error) {
	if e := os.MkdirAll(directory, 0700); e != nil {
		return nil, nil, tls.Certificate{}, e
	}
	caPath := filepath.Join(directory, "ca.pem")
	keyPath := filepath.Join(directory, "ca-key.pem")
	data, e := os.ReadFile(caPath)
	var ca *x509.Certificate
	var key *ecdsa.PrivateKey
	if e == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, nil, tls.Certificate{}, errors.New("E_IDENTITY")
		}
		ca, e = x509.ParseCertificate(block.Bytes)
		if e != nil {
			return nil, nil, tls.Certificate{}, e
		}
		data, e = os.ReadFile(keyPath)
		if e != nil {
			return nil, nil, tls.Certificate{}, e
		}
		block, _ = pem.Decode(data)
		if block == nil {
			return nil, nil, tls.Certificate{}, errors.New("E_IDENTITY")
		}
		key, e = x509.ParseECPrivateKey(block.Bytes)
		if e != nil {
			return nil, nil, tls.Certificate{}, e
		}
	} else if os.IsNotExist(e) {
		key, e = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return nil, nil, tls.Certificate{}, e
		}
		cert := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "CatBridge local authority"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().AddDate(5, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
		encoded, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
		if e != nil {
			return nil, nil, tls.Certificate{}, e
		}
		ca, _ = x509.ParseCertificate(encoded)
		keyBytes, _ := x509.MarshalECPrivateKey(key)
		if e = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}), 0600); e != nil {
			return nil, nil, tls.Certificate{}, e
		}
		if e = os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: encoded}), 0600); e != nil {
			return nil, nil, tls.Certificate{}, e
		}
	} else {
		return nil, nil, tls.Certificate{}, e
	}
	serverPath := filepath.Join(directory, "server.pem")
	serverKey := filepath.Join(directory, "server-key.pem")
	if _, e = os.Stat(serverPath); os.IsNotExist(e) {
		u, e := url.Parse(publicURL)
		if e != nil || u.Scheme != "https" || u.Hostname() == "" {
			return nil, nil, tls.Certificate{}, errors.New("E_URL")
		}
		pair, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return nil, nil, tls.Certificate{}, e
		}
		cert := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "CatBridge"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		if ip := net.ParseIP(u.Hostname()); ip != nil {
			cert.IPAddresses = []net.IP{ip}
		} else {
			cert.DNSNames = []string{u.Hostname()}
		}
		encoded, e := x509.CreateCertificate(rand.Reader, cert, ca, &pair.PublicKey, key)
		if e != nil {
			return nil, nil, tls.Certificate{}, e
		}
		keyBytes, _ := x509.MarshalECPrivateKey(pair)
		if e = os.WriteFile(serverPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: encoded}), 0600); e != nil {
			return nil, nil, tls.Certificate{}, e
		}
		if e = os.WriteFile(serverKey, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}), 0600); e != nil {
			return nil, nil, tls.Certificate{}, e
		}
	}
	server, e := tls.LoadX509KeyPair(serverPath, serverKey)
	return ca, key, server, e
}
func loadTemplates(path string) (map[string]Template, error) {
	list := []Template{}
	if path == "" {
		return map[string]Template{}, nil
	}
	if e := readJSON(path, &list); e != nil {
		return nil, e
	}
	if len(list) > 100 {
		return nil, errors.New("E_SIZE")
	}
	result := map[string]Template{}
	for _, t := range list {
		if !templatePattern.MatchString(t.ID) || !idPattern.MatchString(t.SHA256) || t.Name["pt-BR"] == "" || t.Name["en"] == "" {
			return nil, errors.New("E_TEMPLATE")
		}
		if _, exists := result[t.ID]; exists {
			return nil, errors.New("E_TEMPLATE")
		}
		absolute, e := filepath.Abs(filepath.Join(filepath.Dir(path), t.Path))
		if e != nil {
			return nil, e
		}
		t.Path = absolute
		if e = validateTemplate(t); e != nil {
			return nil, e
		}
		result[t.ID] = t
	}
	return result, nil
}
func validateTemplate(t Template) error {
	data, e := limitedFile(t.Path, 128*1024)
	if e != nil {
		return e
	}
	if len(data) > 128*1024 || hash(data) != t.SHA256 {
		return errors.New("E_TEMPLATE_HASH")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var doc map[string]any
	if e = decoder.Decode(&doc); e != nil {
		return errors.New("E_TEMPLATE")
	}
	var second any
	if decoder.Decode(&second) != io.EOF {
		return errors.New("E_TEMPLATE")
	}
	for key := range doc {
		if key != "id" && key != "info" && key != "http" {
			return errPermission
		}
	}
	blocks, ok := doc["http"].([]any)
	if !ok || len(blocks) == 0 || len(blocks) > 10 {
		return errPermission
	}
	for _, block := range blocks {
		request, ok := block.(map[string]any)
		if !ok {
			return errPermission
		}
		for key := range request {
			if !map[string]bool{"method": true, "path": true, "headers": true, "matchers": true, "extractors": true, "matchers-condition": true, "stop-at-first-match": true}[key] {
				return errPermission
			}
		}
		method, _ := request["method"].(string)
		if method != "GET" && method != "HEAD" {
			return errPermission
		}
		paths, ok := request["path"].([]any)
		if !ok || len(paths) == 0 || len(paths) > 10 {
			return errPermission
		}
		for _, item := range paths {
			path, ok := item.(string)
			if !ok || !strings.HasPrefix(path, "{{BaseURL}}/") || strings.Contains(path, "://") || strings.Contains(path, "interactsh") || strings.ContainsAny(path, "\r\n") {
				return errPermission
			}
		}
		if headers, ok := request["headers"].(map[string]any); ok {
			for key := range headers {
				switch strings.ToLower(key) {
				case "host", "content-length", "transfer-encoding", "connection", "proxy-authorization":
					return errPermission
				}
			}
		}
	}
	return nil
}
func (b *Bridge) capabilities() map[string]any {
	list := make([]Template, 0, len(b.templates))
	for _, t := range b.templates {
		t.Path = ""
		list = append(list, t)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	return map[string]any{"protocol": 2, "catalogVersion": 1, "catalog": b.catalog(), "broker": b.brokerImage, "capabilities": []string{"nuclei.scan"}, "tools": func() []string {
		if b.binary == "" {
			return []string{}
		}
		return []string{"nuclei"}
	}(), "binary": map[string]string{"version": b.version, "sha256": b.binaryHash}, "templates": list, "limits": map[string]int{"rate": 5, "timeout": 600, "targets": 50, "lease": 15, "jobs": 2}, "scope": b.scope, "dataProfiles": []string{"endpoints-only", "selected-headers"}}
}
func (b *Bridge) owner(r *http.Request) (string, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", errPermission
	}
	cert := r.TLS.PeerCertificates[0]
	pool := x509.NewCertPool()
	pool.AddCert(b.ca)
	if _, e := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); e != nil {
		return "", errPermission
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	state, e := b.state()
	if e != nil {
		return "", e
	}
	device, ok := state.Devices[cert.Subject.CommonName]
	if !ok || device.Revoked || device.Serial != cert.SerialNumber.String() {
		return "", errPermission
	}
	return cert.Subject.CommonName, nil
}
func response(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(value)
}
func fail(w http.ResponseWriter, status int, code string) {
	response(w, status, map[string]string{"error": code})
}
func decode(w http.ResponseWriter, r *http.Request, value any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 256*1024)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if e := decoder.Decode(value); e != nil {
		return e
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("E_JSON")
	}
	return nil
}
func (b *Bridge) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v2/pair", b.pair)
	b.resourceRoutes(mux)
	b.resultRoutes(mux)
	mux.HandleFunc("GET /v2/capabilities", func(w http.ResponseWriter, r *http.Request) {
		if _, e := b.owner(r); e != nil {
			fail(w, 403, "E_PAIRING_REVOKED")
			return
		}
		response(w, 200, b.capabilities())
	})
	mux.HandleFunc("POST /v2/revoke", func(w http.ResponseWriter, r *http.Request) {
		owner, e := b.owner(r)
		if e != nil {
			fail(w, 403, "E_PAIRING_REVOKED")
			return
		}
		var input struct {
			ID string `json:"id"`
		}
		if decode(w, r, &input) != nil || input.ID != owner {
			fail(w, 403, "E_PERMISSION")
			return
		}
		b.mu.Lock()
		state, e := b.state()
		if e == nil {
			device := state.Devices[owner]
			device.Revoked = true
			state.Devices[owner] = device
			e = writeJSON(filepath.Join(b.directory, "devices.json"), state)
		}
		for _, job := range b.jobs {
			if job.Owner == owner && job.Status == "running" {
				job.cancel()
			}
		}
		b.mu.Unlock()
		if e != nil {
			fail(w, 500, "E_STORAGE")
			return
		}
		response(w, 200, map[string]bool{"revoked": true})
	})
	mux.HandleFunc("POST /v2/authorizations", b.authorize)
	mux.HandleFunc("POST /v2/jobs", b.start)
	mux.HandleFunc("POST /v2/jobs/{id}/resume", b.resumeJob)
	mux.HandleFunc("GET /v2/jobs/{id}", func(w http.ResponseWriter, r *http.Request) {
		owner, e := b.owner(r)
		if e != nil {
			fail(w, 403, "E_PAIRING_REVOKED")
			return
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		job := b.jobs[r.PathValue("id")]
		if job == nil || job.Owner != owner {
			fail(w, 404, "E_JOB")
			return
		}
		if job.Capability != "nuclei.scan" {
			copy := *job
			copy.Results = nil
			response(w, 200, &copy)
		} else {
			response(w, 200, job)
		}
	})
	mux.HandleFunc("POST /v2/jobs/{id}/{action}", func(w http.ResponseWriter, r *http.Request) {
		owner, e := b.owner(r)
		if e != nil {
			fail(w, 403, "E_PAIRING_REVOKED")
			return
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		job := b.jobs[r.PathValue("id")]
		if job == nil || job.Owner != owner {
			fail(w, 404, "E_JOB")
			return
		}
		switch r.PathValue("action") {
		case "lease":
			if job.Status == "running" {
				job.lease = time.Now().Add(15 * time.Second)
			}
		case "pause":
			if job.Status == "running" {
				job.pauseRequested = true
				job.Status = "pausing"
				job.cancel()
			}
		case "cancel":
			job.pauseRequested = false
			job.cancel()
			if job.Status == "paused" || job.Status == "interrupted" {
				job.Status = "cancelled"
				job.Error = "E_CANCELLED"
				b.persistJob(job)
			}
		default:
			fail(w, 404, "E_METHOD")
			return
		}
		response(w, 200, map[string]string{"id": job.ID, "status": job.Status})
	})
	return b.numericHandler(b.signedHandler(mux))
}
func (b *Bridge) pair(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Code string `json:"code"`
		ID   string `json:"id"`
		CSR  string `json:"csr"`
	}
	if decode(w, r, &input) != nil || len(input.ID) != 36 {
		fail(w, 400, "E_PAIRING")
		return
	}
	csrBytes, e := base64.StdEncoding.DecodeString(input.CSR)
	if e != nil {
		fail(w, 400, "E_PAIRING")
		return
	}
	csr, e := x509.ParseCertificateRequest(csrBytes)
	if e != nil || csr.CheckSignature() != nil || csr.Subject.CommonName != input.ID {
		fail(w, 400, "E_PAIRING")
		return
	}
	if public, ok := csr.PublicKey.(*ecdsa.PublicKey); !ok || public.Curve != elliptic.P256() {
		fail(w, 400, "E_PAIRING")
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	var pairing Pairing
	if readJSON(filepath.Join(b.directory, "pairing.json"), &pairing) != nil || pairing.Protocol != 2 || pairing.Expires <= time.Now().UnixMilli() {
		fail(w, 403, "E_PAIRING_EXPIRED")
		return
	}
	if subtle.ConstantTimeCompare([]byte(pairing.Code), []byte(input.Code)) != 1 {
		pairing.Failures++
		if pairing.Failures >= 5 {
			pairing.Code = ""
			pairing.Expires = 0
		}
		if writeJSON(filepath.Join(b.directory, "pairing.json"), pairing) != nil {
			fail(w, 500, "E_STORAGE")
			return
		}
		fail(w, 403, "E_PAIRING_AUTH")
		return
	}
	state, e := b.state()
	if e != nil || len(state.Devices) >= 100 {
		fail(w, 400, "E_LIMIT")
		return
	}
	if _, exists := state.Devices[input.ID]; exists {
		fail(w, 409, "E_PAIRING")
		return
	}
	cert := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: input.ID}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	encoded, e := x509.CreateCertificate(rand.Reader, cert, b.ca, csr.PublicKey, b.caKey)
	if e != nil {
		fail(w, 500, "E_PAIRING")
		return
	}
	state.Devices[input.ID] = Device{Serial: cert.SerialNumber.String()}
	if e = writeJSON(filepath.Join(b.directory, "devices.json"), state); e != nil {
		fail(w, 500, "E_STORAGE")
		return
	}
	pairing.Code = ""
	pairing.Expires = 0
	if e = writeJSON(filepath.Join(b.directory, "pairing.json"), pairing); e != nil {
		fail(w, 500, "E_STORAGE")
		return
	}
	response(w, 200, map[string]any{"protocol": 2, "id": input.ID, "certificate": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: encoded})), "ca": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b.ca.Raw})), "capabilities": b.capabilities()})
}
func (b *Bridge) validateJob(input JobRequest) ([]Template, error) {
	if input.Capability != "nuclei.scan" {
		return nil, b.validateTool(input)
	}
	if input.Parameters != nil || input.ExpectedImage != "" || input.ExpectedBroker != "" || input.Resource != "" || input.Contract != 0 {
		return nil, errPermission
	}
	if input.Capability != "nuclei.scan" || !regexp.MustCompile(`^[a-f0-9-]{36}$`).MatchString(input.Flow) || !idPattern.MatchString(input.Revision) || !regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`).MatchString(input.Node) || (input.Protection != "PUBLIC" && input.Protection != "PROTECTED" && input.Protection != "SECRET") || !idPattern.MatchString(input.ID) || input.Tool != "nuclei" || !idPattern.MatchString(input.Approval) || (input.DataProfile != "endpoints-only" && input.DataProfile != "selected-headers") || input.Rate < 1 || input.Rate > 5 || input.Timeout < 1 || input.Timeout > 600 || input.Lease != 15 || len(input.Targets) < 1 || len(input.Targets) > 50 || len(input.TemplateIDs) < 1 || len(input.TemplateIDs) > 20 {
		return nil, errPermission
	}

	if len(input.Headers) > 16 || (input.DataProfile == "endpoints-only" && len(input.Headers) > 0) || (input.DataProfile == "selected-headers" && len(input.Headers) == 0) {
		return nil, errPermission
	}
	seenHeaders := map[string]bool{}
	headerBytes := 0
	for _, h := range input.Headers {
		name := strings.ToLower(h.Name)
		headerBytes += len(h.Name) + len(h.Value)
		if !regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$").MatchString(h.Name) || strings.ContainsAny(h.Value, "\r\n\x00") || len(h.Value) > 8192 || headerBytes > 16384 || seenHeaders[name] {
			return nil, errPermission
		}
		seenHeaders[name] = true
		if (name == "authorization" || name == "cookie" || name == "x-api-key" || name == "api-key") && input.Protection != "SECRET" {
			return nil, errors.New("E_CREDENTIAL_PROTECTION")
		}
		switch name {
		case "host", "content-length", "transfer-encoding", "connection", "proxy-authorization", "proxy-connection", "upgrade", "te", "trailer":
			return nil, errPermission
		}
	}
	if input.ExpectedBinary != b.binaryHash {
		return nil, errors.New("E_TOOL_CHANGED")
	}
	for _, target := range input.Targets {
		if len(target) > 8192 || strings.ContainsAny(target, "\r\n") || !allows(b.scope, target) || !allows(input.Scope, target) {
			return nil, errors.New("E_HOST")
		}
	}
	result := []Template{}
	for _, id := range input.TemplateIDs {
		template, ok := b.templates[id]
		if !ok || input.ExpectedTemplates[id] != template.SHA256 {
			return nil, errors.New("E_TEMPLATE_HASH")
		}
		if e := validateTemplate(template); e != nil {
			return nil, e
		}
		result = append(result, template)
	}
	if b.binary == "" {
		return nil, errors.New("E_TOOL_UNAVAILABLE")
	}
	digest, e := fileHash(b.binary)
	if e != nil || digest != b.binaryHash {
		return nil, errors.New("E_TOOL_CHANGED")
	}
	return result, nil
}
func (b *Bridge) start(w http.ResponseWriter, r *http.Request) {
	owner, e := b.owner(r)
	if e != nil {
		fail(w, 403, "E_PAIRING_REVOKED")
		return
	}
	var input JobRequest
	if decode(w, r, &input) != nil {
		fail(w, 400, "E_JOB")
		return
	}
	templates, e := b.validateJob(input)
	if e != nil {
		fail(w, 400, e.Error())
		return
	}
	if input.Capability != "nuclei.scan" && input.Resource != "" {
		if _, e = b.resourceFor(input, owner); e != nil {
			fail(w, 403, e.Error())
			return
		}
	}
	if e = b.verifyAuthorization(input, owner); e != nil {
		fail(w, 403, e.Error())
		return
	}
	digest := jobDefinition(input)
	b.mu.Lock()
	if old := b.jobs[input.ID]; old != nil {
		if old.Owner != owner || old.Digest != digest {
			b.mu.Unlock()
			fail(w, 409, "E_IDEMPOTENCY")
			return
		}
		response(w, 200, old)
		b.mu.Unlock()
		return
	}
	select {
	case b.slots <- struct{}{}:
	default:
		b.mu.Unlock()
		fail(w, 429, "E_QUEUE")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(input.Timeout)*time.Second)
	hashes := map[string]string{}
	for _, t := range templates {
		hashes[t.ID] = t.SHA256
	}
	batches := planBatches(input, templates)
	binaryInfo := map[string]string{"version": b.version, "sha256": b.binaryHash}
	if input.Capability != "nuclei.scan" {
		batches = toolBatches(input)
		image := b.tools[input.Tool]
		binaryInfo = map[string]string{"version": image.Version, "sha256": image.Binary, "image": image.Image, "broker": b.brokerImage.Image}
	}
	job := &Job{Resource: input.Resource, Flow: input.Flow, Revision: input.Revision, Node: input.Node, Capability: input.Capability, Protection: input.Protection, DefinitionHash: digest, Batches: batches, ID: input.ID, Owner: owner, Digest: digest, Status: "running", Started: time.Now().UnixMilli(), Results: []json.RawMessage{}, Binary: binaryInfo, Templates: hashes, lease: time.Now().Add(15 * time.Second), cancel: cancel}
	b.jobs[input.ID] = job
	if e = b.persistJob(job); e != nil {
		delete(b.jobs, input.ID)
		<-b.slots
		cancel()
		b.mu.Unlock()
		fail(w, 500, "E_STORAGE")
		return
	}
	if input.Capability != "nuclei.scan" {
		copy := *job
		copy.Results = nil
		response(w, 202, &copy)
	} else {
		response(w, 202, job)
	}
	b.mu.Unlock()
	go b.launch(job, input, templates, ctx, cancel)
}
func (b *Bridge) launch(job *Job, input JobRequest, templates []Template, ctx context.Context, cancel context.CancelFunc) {
	owner := job.Owner
	segment := time.Now()
	defer func() { cancel(); <-b.slots }()
	monitorDone := make(chan struct{})
	defer close(monitorDone)
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				b.mu.Lock()
				expired := input.Protection != "PUBLIC" && time.Now().After(job.lease)
				state, e := b.state()
				revoked := e != nil || state.Devices[owner].Revoked
				b.mu.Unlock()
				if expired || revoked {
					if expired {
						b.mu.Lock()
						job.pauseRequested = true
						job.Status = "pausing"
						b.mu.Unlock()
					}
					cancel()
					return
				}
			case <-ctx.Done():
				return
			case <-monitorDone:
				return
			}
		}
	}()
	total := 0
	err := b.executeBatches(ctx, input, templates, job, func(line json.RawMessage) error {
		if !json.Valid(line) || len(line) > 128*1024 {
			return errors.New("E_RESULT")
		}
		total += len(line)
		if total > 768*1024 {
			return errors.New("E_SIZE")
		}
		var finding map[string]any
		if json.Unmarshal(line, &finding) != nil {
			return errors.New("E_RESULT")
		}
		target, _ := finding["matched-at"].(string)
		if target == "" {
			target, _ = finding["host"].(string)
		}
		if input.Capability != "nuclei.scan" {
			target, _ = finding["url"].(string)
			if target == "" && finding["kind"] == "api_test" {
				target = input.Targets[0]
			}
		}
		if !allows(input.Scope, target) || !allows(b.scope, target) {
			if input.Tool == "katana" && finding["kind"] == "endpoint" {
				finding["blocked"] = true
				finding["fetched"] = false
			} else {
				return errors.New("E_HOST")
			}
		}
		if input.Capability != "nuclei.scan" {
			finding["capability"] = input.Capability
			finding["tool"] = input.Tool
			finding["toolVersion"] = b.tools[input.Tool].Version
			finding["flow"] = input.Flow
			finding["revision"] = input.Revision
			finding["node"] = input.Node
		}
		delete(finding, "request")
		delete(finding, "response")
		delete(finding, "curl-command")
		redacted, _ := json.Marshal(finding)
		b.mu.Lock()
		defer b.mu.Unlock()
		if len(job.Results) >= 1000 {
			return errors.New("E_SIZE")
		}
		job.Results = append(job.Results, redacted)
		return nil
	})
	b.mu.Lock()
	defer b.mu.Unlock()
	job.Spent += time.Since(segment).Milliseconds()
	job.Finished = time.Now().UnixMilli()
	job.Status = "complete"
	if err != nil {
		job.Status = "error"
		job.Error = "E_CONNECTOR"
		if strings.HasPrefix(err.Error(), "E_") {
			job.Error = err.Error()
		}
		if ctx.Err() != nil {
			job.Status = "cancelled"
			job.Error = "E_CANCELLED"
			if job.pauseRequested {
				job.Status = "paused"
				job.Error = "E_UNKNOWN_RESULT"
			}
		}
	}
	if e := b.persistJob(job); e != nil {
		job.Status = "error"
		job.Error = "E_STORAGE"
	}
	if len(b.jobs) > 200 {
		var oldest *Job
		for _, candidate := range b.jobs {
			if candidate.Status != "running" && (oldest == nil || candidate.Started < oldest.Started) {
				oldest = candidate
			}
		}
		if oldest != nil {
			delete(b.jobs, oldest.ID)
			os.Remove(filepath.Join(b.directory, "jobs", oldest.ID+".json"))
		}
	}
}

func (b *Bridge) executeNuclei(ctx context.Context, input JobRequest, templates []Template, emit func(json.RawMessage) error) error {
	proxy, stop, e := guardedEgress(ctx, input)
	if e != nil {
		return e
	}
	defer stop()
	args := []string{"-jsonl", "-silent", "-nc", "-ni", "-duc", "-dr", "-no-stdin", "-rate-limit", fmt.Sprint(input.Rate), "-c", "1", "-bulk-size", "1", "-timeout", "10", "-retries", "0", "-proxy", proxy, "-proxy-internal"}
	for _, target := range input.Targets {
		args = append(args, "-u", target)
	}
	for _, t := range templates {
		args = append(args, "-t", t.Path)
	}
	cmd := exec.CommandContext(ctx, b.binary, args...)
	cmd.Env = append(minimalEnvironment(), "NO_COLOR=1", "DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD=true", "DISABLE_NUCLEI_TEMPLATES_GITHUB_DOWNLOAD=true", "DISABLE_NUCLEI_TEMPLATES_GITLAB_DOWNLOAD=true", "DISABLE_NUCLEI_TEMPLATES_AWS_DOWNLOAD=true", "DISABLE_NUCLEI_TEMPLATES_AZURE_DOWNLOAD=true")
	configDirectory, e := os.MkdirTemp(b.directory, ".nuclei-task-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(configDirectory)
	configPath := filepath.Join(configDirectory, "config.yaml")
	if e = os.WriteFile(configPath, func() []byte {
		config := map[string]any{"disable-update-check": true, "no-interactsh": true, "disable-redirects": true}
		headers := []string{}
		for _, h := range input.Headers {
			headers = append(headers, h.Name+": "+h.Value)
		}
		if len(headers) > 0 {
			config["header"] = headers
		}
		data, _ := yaml.Marshal(config)
		return data
	}(), 0600); e != nil {
		return e
	}
	cmd.Args = append(cmd.Args, "-config", configPath)
	cmd.Stderr = io.Discard
	pipe, e := cmd.StdoutPipe()
	if e != nil {
		return e
	}
	if e = cmd.Start(); e != nil {
		return e
	}
	scanner := bufio.NewScanner(io.LimitReader(pipe, 10*1024*1024))
	scanner.Buffer(make([]byte, 8192), 128*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		if e = emit(append(json.RawMessage{}, line...)); e != nil {
			cmd.Process.Kill()
			cmd.Wait()
			return e
		}
	}
	if e = scanner.Err(); e != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return e
	}
	return cmd.Wait()
}
func makePairing(b *Bridge, language ...string) error {
	code, e := numericCode()
	if e != nil {
		return e
	}
	pairing := Pairing{Protocol: 2, URL: b.publicURL, Fingerprint: hash(b.serverCertificate.Certificate[0]), Code: code, Expires: time.Now().Add(2 * time.Minute).UnixMilli(), Name: "CatBridge"}
	if e := writeJSON(filepath.Join(b.directory, "pairing.json"), pairing); e != nil {
		return e
	}
	groups := []string{}
	for i := 0; i < len(code); i += 4 {
		groups = append(groups, code[i:i+4])
	}
	if len(language) > 0 && language[0] == "en" {
		fmt.Printf("Address: %s\nPairing code: %s\nOpen Extensions > Connections > Pair CatBridge. The code expires in two minutes and works once.\n", b.publicURL, strings.Join(groups, " "))
	} else {
		fmt.Printf("Endereço: %s\nCódigo de pareamento: %s\nAbra Extensões > Conexões > Parear CatBridge. O código expira em dois minutos e funciona uma vez.\n", b.publicURL, strings.Join(groups, " "))
	}
	return nil
}
func limitedFile(path string, limit int64) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("E_SIZE")
	}
	data, e := io.ReadAll(io.LimitReader(f, limit+1))
	if len(data) > int(limit) {
		return nil, errors.New("E_SIZE")
	}
	return data, e
}
func fileHash(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() > 512*1024*1024 {
		return "", errors.New("E_SIZE")
	}
	digest := sha256.New()
	if _, e = io.Copy(digest, io.LimitReader(f, 512*1024*1024+1)); e != nil {
		return "", e
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

type StoredJob struct {
	Owner  string `json:"owner"`
	Digest string `json:"digest"`
	Job    *Job   `json:"job"`
}

func (b *Bridge) persistJob(job *Job) error {
	directory := filepath.Join(b.directory, "jobs")
	if e := os.MkdirAll(directory, 0700); e != nil {
		return e
	}
	return b.writePrivate(filepath.Join(directory, job.ID+".json"), StoredJob{Owner: job.Owner, Digest: job.Digest, Job: job})
}
func (b *Bridge) restoreJobs() error {
	files, e := os.ReadDir(filepath.Join(b.directory, "jobs"))
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	if len(files) > 201 {
		return errors.New("E_SIZE")
	}
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".json") {
			continue
		}
		var stored StoredJob
		if e = b.readPrivate(filepath.Join(b.directory, "jobs", file.Name()), &stored); e != nil {
			return e
		}
		job := stored.Job
		if job == nil || !idPattern.MatchString(job.ID) || !idPattern.MatchString(stored.Digest) || len(stored.Owner) != 36 {
			return errors.New("E_JOB")
		}
		job.Owner = stored.Owner
		job.Digest = stored.Digest
		job.cancel = func() {}
		if job.Status == "running" || job.Status == "pausing" {
			for i := range job.Batches {
				if job.Batches[i].Status == "running" {
					job.Batches[i].Status = "unknown"
				}
			}
			job.Status = "interrupted"
			job.Error = "E_UNKNOWN_RESULT"
			job.Finished = time.Now().UnixMilli()
			if e = b.persistJob(job); e != nil {
				return e
			}
		}
		b.jobs[job.ID] = job
	}
	return nil
}
func main() {
	if len(os.Args) > 1 && (os.Args[1] == "broker" || os.Args[1] == "runner") {
		if e := runtimeEntry(os.Args[1]); e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(2)
		}
		return
	}
	command := "serve"
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
		command = os.Args[1]
		os.Args = append([]string{os.Args[0]}, os.Args[2:]...)
	}
	defaultDir, e := os.UserConfigDir()
	if e != nil {
		panic(e)
	}
	directory := flag.String("state", filepath.Join(defaultDir, "CatBridge"), "Pasta de identidade / Identity directory")
	listen := flag.String("listen", "127.0.0.1:8743", "Endereço local / Listen address")
	public := flag.String("public", "https://127.0.0.1:8743", "Endereço usado pelo celular / Address used by phone")
	scope := flag.String("scope", "", "Destinos permitidos separados por vírgula / Allowed destinations separated by commas")
	binary := flag.String("nuclei", "", "Caminho absoluto do Nuclei / Absolute Nuclei executable")
	templates := flag.String("templates", "", "Manifesto de templates revisados / Reviewed template manifest")
	dockerHost := flag.String("docker-host", "", "Endpoint Docker do administrador / Administrator Docker endpoint")
	toolLock := flag.String("tool-lock", "", "Manifesto assinado dos executores / Signed executor manifest")
	toolKey := flag.String("tool-key", "", "Impressão digital da chave / Signing key fingerprint")
	runtimeNetwork := flag.String("runtime-network", "bridge", "Rede de saída do intermediário / Broker egress network")
	upstreamCA := flag.String("upstream-ca", "", "CA adicional confiável / Additional trusted CA")
	device := flag.String("device", "", "Identificador do aparelho / Device identifier")
	lang := flag.String("lang", "pt-BR", "pt-BR ou en / pt-BR or en")
	flag.Parse()
	if command == "serve" {
		release, e := acquireHostLock(*directory)
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		defer release()
	}
	ca, key, server, e := identity(*directory, *public)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	b := &Bridge{directory: *directory, publicURL: *public, ca: ca, caKey: key, serverCertificate: server, jobs: map[string]*Job{}, slots: make(chan struct{}, 2), templates: map[string]Template{}}
	if command == "pair" {
		if e = makePairing(b, *lang); e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		return
	}
	if command == "revoke" {
		state, e := b.state()
		if e != nil {
			panic(e)
		}
		d, ok := state.Devices[*device]
		if !ok {
			fmt.Fprintln(os.Stderr, "E_DEVICE")
			os.Exit(1)
		}
		d.Revoked = true
		state.Devices[*device] = d
		if e = writeJSON(filepath.Join(*directory, "devices.json"), state); e != nil {
			panic(e)
		}
		return
	}
	if command != "serve" {
		fmt.Fprintln(os.Stderr, "serve | pair | revoke")
		os.Exit(1)
	}
	if *scope != "" {
		b.scope = strings.Split(*scope, ",")
		for i := range b.scope {
			b.scope[i] = strings.TrimSpace(b.scope[i])
		}
	}
	b.templates, e = loadTemplates(*templates)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	if *binary != "" {
		if !filepath.IsAbs(*binary) {
			fmt.Fprintln(os.Stderr, "E_PATH")
			os.Exit(1)
		}
		b.binary = *binary
		digest, e := fileHash(*binary)
		if e != nil {
			panic(e)
		}
		b.binaryHash = digest
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		output, e := exec.CommandContext(ctx, *binary, "-version").CombinedOutput()
		if e != nil {
			fmt.Fprintln(os.Stderr, "E_TOOL_UNAVAILABLE")
			os.Exit(1)
		}
		b.version = strings.TrimSpace(string(output))
		if !strings.Contains(b.version, "3.") {
			fmt.Fprintln(os.Stderr, "E_TOOL_VERSION")
			os.Exit(1)
		}
	}
	if e = b.restoreJobs(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	b.dockerHost = *dockerHost
	b.runtimeNetwork = *runtimeNetwork
	b.upstreamCA = *upstreamCA
	if e = b.loadToolLock(*toolLock, *toolKey); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	b.execute = b.executeNuclei
	if e = makePairing(b, *lang); e != nil {
		panic(e)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	s := &http.Server{Addr: *listen, Handler: b.handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{server}, ClientAuth: tls.RequestClientCert, ClientCAs: pool}}
	if *lang == "en" {
		fmt.Printf("CatBridge ready at %s; pairing expires in two minutes.\n", *public)
	} else {
		fmt.Printf("CatBridge disponível em %s; o pareamento expira em dois minutos.\n", *public)
	}
	if e = s.ListenAndServeTLS("", ""); e != nil && !errors.Is(e, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
