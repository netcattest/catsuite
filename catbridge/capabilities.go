package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
)

type ToolImage struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Image   string `json:"image"`
	Binary  string `json:"binarySha256"`
}
type ToolLock struct {
	Format    string      `json:"format"`
	Version   int         `json:"version"`
	Broker    ToolImage   `json:"broker"`
	Tools     []ToolImage `json:"tools"`
	Signature struct {
		PublicKey string `json:"publicKey"`
		Value     string `json:"value"`
	} `json:"signature"`
}
type ToolParameters struct {
	Profile      string   `json:"profile"`
	Methods      []string `json:"methods"`
	Operations   []string `json:"operations,omitempty"`
	Depth        int      `json:"depth,omitempty"`
	Pages        int      `json:"pages,omitempty"`
	Requests     int      `json:"requests"`
	Examples     int      `json:"examples,omitempty"`
	Seed         int64    `json:"seed,omitempty"`
	Paths        []string `json:"paths,omitempty"`
	Providers    []string `json:"providers,omitempty"`
	Ports        []int    `json:"ports,omitempty"`
	RecordTypes  []string `json:"recordTypes,omitempty"`
	Patterns     []string `json:"patterns,omitempty"`
	Parameter    string   `json:"parameter,omitempty"`
	VirtualHosts []string `json:"virtualHosts,omitempty"`
	MaxResults   int      `json:"maxResults,omitempty"`
}
type Capability struct {
	ID        string               `json:"id"`
	Area      string               `json:"area"`
	Stage     int                  `json:"stage"`
	Title     map[string]string    `json:"title"`
	Engines   []string             `json:"engines"`
	Inputs    []string             `json:"inputs"`
	Outputs   []string             `json:"outputs"`
	State     string               `json:"state"`
	Contract  int                  `json:"contractVersion"`
	Schema    map[string]any       `json:"parametersSchema,omitempty"`
	Executor  *ToolImage           `json:"executor,omitempty"`
	Executors map[string]ToolImage `json:"executors,omitempty"`
	Limits    map[string]int       `json:"limits,omitempty"`
}

var toolVersions = map[string]string{"httpx": "1.12.0", "katana": "1.7.0", "schemathesis": "4.29.1"}
var toolCapabilities = map[string]string{"httpx": "http.probe", "katana": "web.crawl", "schemathesis": "api.schema.test"}

func textPair(pt, en string) map[string]string { return map[string]string{"pt-BR": pt, "en": en} }
func capabilityCatalog() []Capability {
	return []Capability{
		{ID: "http.probe", Area: "http", Stage: 1, Title: textPair("Identificar serviços HTTP", "Identify HTTP services"), Engines: []string{"httpx"}, Inputs: []string{"endpoint", "http"}, Outputs: []string{"endpoint", "analysis"}, Contract: 1},
		{ID: "web.crawl", Area: "http", Stage: 1, Title: textPair("Mapear páginas e JavaScript", "Map pages and JavaScript"), Engines: []string{"katana"}, Inputs: []string{"endpoint", "http"}, Outputs: []string{"endpoint", "analysis"}, Contract: 1},
		{ID: "api.schema.test", Area: "api", Stage: 1, Title: textPair("Testar contrato OpenAPI", "Test OpenAPI contract"), Engines: []string{"schemathesis"}, Inputs: []string{"endpoint", "openapi"}, Outputs: []string{"analysis", "finding"}, Contract: 1},
		{ID: "nuclei.scan", Area: "security", Stage: 0, Title: textPair("Analisar templates revisados", "Analyze reviewed templates"), Engines: []string{"nuclei"}, Inputs: []string{"endpoint", "http"}, Outputs: []string{"analysis"}, Contract: 1},
		{ID: "assets.subdomains.discover", Area: "assets", Stage: 2, Title: textPair("Descobrir subdomínios", "Discover subdomains"), Engines: []string{"subfinder", "amass"}, Inputs: []string{"record", "endpoint", "http"}, Outputs: []string{"record"}, Contract: 1},
		{ID: "dns.resolve", Area: "dns", Stage: 2, Title: textPair("Resolver DNS", "Resolve DNS"), Engines: []string{"dnsx", "amass"}, Inputs: []string{"record", "endpoint", "http"}, Outputs: []string{"record"}, Contract: 1},
		{ID: "dns.enumerate", Area: "dns", Stage: 2, Title: textPair("Enumerar DNS", "Enumerate DNS"), Engines: []string{"dnsx", "amass"}, Inputs: []string{"record", "endpoint", "http"}, Outputs: []string{"record"}, Contract: 1},
		{ID: "dns.permute", Area: "dns", Stage: 2, Title: textPair("Gerar permutações", "Generate permutations"), Engines: []string{"alterx"}, Inputs: []string{"record", "endpoint", "http"}, Outputs: []string{"record"}, Contract: 1},
		{ID: "urls.history", Area: "assets", Stage: 2, Title: textPair("Consultar URLs históricas", "Query historical URLs"), Engines: []string{"gau", "waybackurls"}, Inputs: []string{"record", "endpoint", "http"}, Outputs: []string{"endpoint"}, Contract: 1},
		{ID: "assets.search", Area: "assets", Stage: 2, Title: textPair("Consultar fontes externas", "Query external sources"), Engines: []string{"uncover"}, Inputs: []string{"record", "endpoint", "http"}, Outputs: []string{"record"}, Contract: 1},
		{ID: "net.ports.discover", Area: "network", Stage: 3, Title: textPair("Descobrir portas TCP", "Discover TCP ports"), Engines: []string{"naabu", "nmap"}, Inputs: []string{"record", "endpoint", "http"}, Outputs: []string{"record"}, Contract: 1},
		{ID: "net.services.fingerprint", Area: "network", Stage: 3, Title: textPair("Identificar serviços", "Identify services"), Engines: []string{"nmap"}, Inputs: []string{"record", "endpoint", "http"}, Outputs: []string{"record"}, Contract: 1},
		{ID: "web.paths.fuzz", Area: "http", Stage: 3, Title: textPair("Descobrir caminhos", "Discover paths"), Engines: []string{"ffuf"}, Inputs: []string{"endpoint"}, Outputs: []string{"endpoint"}, Contract: 1},
		{ID: "http.parameters.fuzz", Area: "http", Stage: 3, Title: textPair("Testar parâmetros HTTP", "Fuzz HTTP parameters"), Engines: []string{"ffuf"}, Inputs: []string{"http"}, Outputs: []string{"analysis"}, Contract: 1},
		{ID: "web.vhosts.fuzz", Area: "http", Stage: 3, Title: textPair("Descobrir hosts virtuais", "Discover virtual hosts"), Engines: []string{"ffuf"}, Inputs: []string{"endpoint"}, Outputs: []string{"endpoint"}, Contract: 1},
		{ID: "http.parameters.discover", Area: "http", Stage: 3, Title: textPair("Descobrir parâmetros HTTP", "Discover HTTP parameters"), Engines: []string{"arjun"}, Inputs: []string{"endpoint", "http"}, Outputs: []string{"analysis"}, Contract: 1},
		{ID: "web.xss.analyze", Area: "security", Stage: 4, Title: textPair("Analisar XSS", "Analyze XSS"), Engines: []string{"dalfox"}, Inputs: []string{"http"}, Outputs: []string{"analysis", "finding"}, Contract: 1},
		{ID: "api.sqli.validate", Area: "security", Stage: 4, Title: textPair("Validar suspeitas de SQL injection", "Validate suspected SQL injection"), Engines: []string{"sqlmap"}, Inputs: []string{"http"}, Outputs: []string{"analysis", "finding"}, Contract: 1},
		{ID: "jwt.analyze", Area: "security", Stage: 4, Title: textPair("Analisar JWT", "Analyze JWT"), Engines: []string{"jwt_tool"}, Inputs: []string{"jwt", "http"}, Outputs: []string{"analysis", "jwt", "finding"}, Contract: 1},
		{ID: "tls.assess", Area: "network", Stage: 4, Title: textPair("Analisar TLS e SSL", "Assess TLS and SSL"), Engines: []string{"testssl"}, Inputs: []string{"endpoint"}, Outputs: []string{"analysis", "finding"}, Contract: 1},
		{ID: "web.server.assess", Area: "security", Stage: 4, Title: textPair("Analisar servidor web", "Assess web server"), Engines: []string{"nikto"}, Inputs: []string{"endpoint"}, Outputs: []string{"analysis", "finding"}, Contract: 1},
		{ID: "code.secrets.scan", Area: "code", Stage: 5, Title: textPair("Encontrar candidatos a segredos", "Find secret candidates"), Engines: []string{"trufflehog", "gitleaks"}, Inputs: []string{"record", "endpoint", "http"}, Outputs: []string{"secret", "finding"}, Contract: 1},
		{ID: "code.sast.scan", Area: "code", Stage: 5, Title: textPair("Analisar código estático", "Analyze source code"), Engines: []string{"semgrep"}, Inputs: []string{"record", "endpoint", "http"}, Outputs: []string{"analysis", "finding"}, Contract: 1},
	}
}
func parameterSchema(cap string) map[string]any {
	props := map[string]any{"profile": map[string]any{"type": "string", "enum": []string{"read-only", "mutation-approved"}}, "methods": map[string]any{"type": "array", "items": map[string]any{"type": "string", "enum": []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}}}, "requests": map[string]any{"type": "integer", "minimum": 1, "maximum": 1000}}
	if cap == "web.crawl" {
		props["depth"] = map[string]any{"type": "integer", "minimum": 1, "maximum": 2}
		props["pages"] = map[string]any{"type": "integer", "minimum": 1, "maximum": 25}
	}
	if cap == "api.schema.test" {
		props["operations"] = map[string]any{"type": "array", "maxItems": 20, "items": map[string]any{"type": "string"}}
		props["examples"] = map[string]any{"type": "integer", "minimum": 1, "maximum": 25}
		props["seed"] = map[string]any{"type": "integer", "minimum": 0}
		props["paths"] = map[string]any{"type": "array", "maxItems": 20, "items": map[string]any{"type": "string"}}
	}
	return map[string]any{"type": "object", "additionalProperties": false, "properties": props, "required": []string{"profile", "methods", "requests"}}
}
func (b *Bridge) catalog() []Capability {
	list := capabilityCatalog()
	for i := range list {
		c := &list[i]
		c.State = "planned"
		if c.ID == "nuclei.scan" {
			c.State = "not-installed"
			if b.binary != "" {
				c.State = "available"
			}
			continue
		}
		c.State = "not-installed"
		c.Schema = parameterSchema(c.ID)
		if c.Stage > 1 {
			c.Contract = 2
			c.Schema = ecosystemParameterSchema(c.ID)
		}
		c.Limits = map[string]int{"rate": 5, "targets": 50, "timeout": 120, "connections": 2, "requests": 1000}
		if c.ID == "web.crawl" {
			c.Limits["requests"] = 100
			c.Limits["pages"] = 25
			c.Limits["depth"] = 2
		}
		if c.ID == "api.schema.test" {
			c.Limits["timeout"] = 300
			c.Limits["targets"] = 1
			c.Limits["operations"] = 20
			c.Limits["examples"] = 25
		}
		if c.Stage > 1 {
			c.Limits["timeout"] = 300
			c.Limits["targets"] = 25
			c.Limits["requests"] = 500
			c.Limits["maxResults"] = 1000
			c.Limits["resourceBytes"] = 2 * 1024 * 1024
			c.Limits["ports"] = 32
		}
		c.Executors = map[string]ToolImage{}
		engines := []string{}
		for _, engine := range c.Engines {
			if !supportsTool(engine, c.ID) {
				continue
			}
			engines = append(engines, engine)
			if image, ok := b.tools[engine]; ok {
				c.Executors[engine] = image
				if c.Executor == nil {
					copy := image
					c.Executor = &copy
				}
				c.State = "available"
			}
		}
		c.Engines = engines
		if c.Executor != nil && b.runtimeError != "" {
			c.State = "unavailable"
		}
	}
	return list
}
func (b *Bridge) loadToolLock(path, fingerprint string) error {
	if path == "" {
		return nil
	}
	data, e := limitedFile(path, 128*1024)
	if e != nil {
		return e
	}
	var lock ToolLock
	if json.Unmarshal(data, &lock) != nil || lock.Format != "catbridge-tools" || lock.Version != 1 {
		return errors.New("E_TOOL_LOCK")
	}
	public, e := base64.StdEncoding.Strict().DecodeString(lock.Signature.PublicKey)
	if e != nil || len(public) != 32 || hash(public) != fingerprint {
		return errors.New("E_SIGNATURE")
	}
	sig, e := base64.StdEncoding.Strict().DecodeString(lock.Signature.Value)
	if e != nil {
		return errors.New("E_SIGNATURE")
	}
	var doc map[string]any
	json.Unmarshal(data, &doc)
	delete(doc, "signature")
	canonical, e := json.Marshal(doc)
	if e != nil || !ed25519.Verify(public, canonical, sig) {
		return errors.New("E_SIGNATURE")
	}
	if lock.Broker.ID != "catsuite.broker" || !regexp.MustCompile(`^sha256:[a-f0-9]{64}$`).MatchString(lock.Broker.Image) || !idPattern.MatchString(lock.Broker.Binary) {
		return errors.New("E_TOOL_LOCK")
	}
	b.tools = map[string]ToolImage{}
	b.brokerImage = lock.Broker
	for _, tool := range lock.Tools {
		if toolVersions[tool.ID] != tool.Version || !regexp.MustCompile(`^sha256:[a-f0-9]{64}$`).MatchString(tool.Image) || !idPattern.MatchString(tool.Binary) {
			return errors.New("E_TOOL_LOCK")
		}
		if _, ok := b.tools[tool.ID]; ok {
			return errors.New("E_TOOL_LOCK")
		}
		b.tools[tool.ID] = tool
	}
	b.docker, e = exec.LookPath("docker")
	if e != nil {
		b.runtimeError = "E_RUNTIME_UNAVAILABLE"
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, e := b.dockerOutput(ctx, "info", "--format", "{{.OSType}}")
	if e != nil || strings.TrimSpace(string(out)) != "linux" {
		b.runtimeError = "E_RUNTIME_UNAVAILABLE"
	}
	return nil
}
func (b *Bridge) validateTool(input JobRequest) error {
	if _, ok := ecosystemVersions[input.Tool]; ok {
		return b.validateEcosystem(input)
	}
	if toolCapabilities[input.Tool] != input.Capability || !idPattern.MatchString(input.ID) || !regexp.MustCompile(`^[a-f0-9-]{36}$`).MatchString(input.Flow) || !idPattern.MatchString(input.Revision) || !regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`).MatchString(input.Node) || !idPattern.MatchString(input.Approval) || input.Lease != 15 || input.Rate < 1 || input.Rate > 5 || input.Timeout < 1 || input.Timeout > 300 || input.Tool != "schemathesis" && input.Timeout > 120 || len(input.Targets) < 1 || len(input.Targets) > 50 || input.Parameters == nil {
		return errPermission
	}
	if input.Protection != "PUBLIC" && input.Protection != "PROTECTED" && input.Protection != "SECRET" {
		return errPermission
	}
	image, ok := b.tools[input.Tool]
	if !ok {
		return errors.New("E_TOOL_UNAVAILABLE")
	}
	if b.runtimeError != "" {
		return errors.New(b.runtimeError)
	}
	if input.ExpectedImage != image.Image || input.ExpectedBinary != image.Binary || input.ExpectedBroker != b.brokerImage.Image || input.Contract != 1 {
		return errors.New("E_TOOL_CHANGED")
	}
	if len(input.TemplateIDs) > 0 || len(input.ExpectedTemplates) > 0 || len(input.Headers) > 16 || (input.DataProfile != "endpoints-only" && input.DataProfile != "selected-headers") {
		return errPermission
	}
	p := input.Parameters
	if p.Requests < 1 || p.Requests > 1000 || len(p.Methods) < 1 || len(p.Methods) > 7 {
		return errPermission
	}
	if p.Profile != "read-only" && p.Profile != "mutation-approved" {
		return errPermission
	}
	seen := map[string]bool{}
	for _, method := range p.Methods {
		if seen[method] || !strings.Contains("|GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS|", "|"+method+"|") {
			return errPermission
		}
		seen[method] = true
		if method != "GET" && method != "HEAD" && (input.Tool != "schemathesis" || p.Profile != "mutation-approved") {
			return errPermission
		}
	}
	if input.Tool != "schemathesis" && (p.Profile != "read-only" || len(p.Operations) > 0 || len(p.Paths) > 0 || p.Examples != 0 || p.Seed != 0 || input.Resource != "") {
		return errPermission
	}
	if input.Tool == "katana" && (p.Depth < 1 || p.Depth > 2 || p.Pages < 1 || p.Pages > 25 || p.Requests > 100) {
		return errPermission
	}
	if input.Tool == "httpx" && (p.Depth != 0 || p.Pages != 0) {
		return errPermission
	}
	if input.Tool == "schemathesis" && (len(input.Targets) != 1 || p.Depth != 0 || p.Pages != 0 || p.Examples < 1 || p.Examples > 25 || p.Seed < 0 || len(p.Operations) < 1 || len(p.Operations) > 20 || len(p.Paths) != len(p.Operations) || !idPattern.MatchString(input.Resource)) {
		return errPermission
	}
	for _, path := range p.Paths {
		if len(path) > 2048 || !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#\r\n\\\x00") {
			return errPermission
		}
	}
	for _, operation := range p.Operations {
		if len(operation) > 512 || strings.ContainsAny(operation, "\r\n\x00") {
			return errPermission
		}
	}
	headerBytes := 0
	names := map[string]bool{}
	for _, h := range input.Headers {
		name := strings.ToLower(h.Name)
		headerBytes += len(h.Name) + len(h.Value)
		if !regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$").MatchString(h.Name) || strings.ContainsAny(h.Value, "\r\n\x00") || len(h.Value) > 8192 || headerBytes > 16384 || names[name] {
			return errPermission
		}
		names[name] = true
		if name == "authorization" || name == "cookie" || name == "x-api-key" || name == "api-key" {
			if input.Protection != "SECRET" {
				return errors.New("E_CREDENTIAL_PROTECTION")
			}
		}
		if strings.Contains("|host|content-length|transfer-encoding|connection|proxy-authorization|proxy-connection|upgrade|te|trailer|", "|"+name+"|") {
			return errPermission
		}
	}
	if (len(input.Headers) == 0) != (input.DataProfile == "endpoints-only") {
		return errPermission
	}
	for _, target := range input.Targets {
		u, e := url.Parse(target)
		if e != nil || u.User != nil || u.Fragment != "" || len(target) > 8192 || !allows(input.Scope, target) || !allows(b.scope, target) {
			return errors.New("E_HOST")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, imageID := range []string{image.Image, b.brokerImage.Image} {
		out, e := b.dockerOutput(ctx, "image", "inspect", "--format", "{{.Id}}", imageID)
		if e != nil || strings.TrimSpace(string(out)) != imageID {
			return errors.New("E_TOOL_CHANGED")
		}
	}
	return nil
}
func normalizeToolParameters(raw []byte) (*ToolParameters, error) {
	var value ToolParameters
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&value) != nil {
		return nil, errPermission
	}
	return &value, nil
}
func toolBatches(input JobRequest) []Batch {
	targets := append([]string{}, input.Targets...)
	sort.Strings(targets)
	out := []Batch{}
	if input.Tool == "schemathesis" {
		for i, operation := range input.Parameters.Operations {
			data, _ := json.Marshal([]string{operation, input.Parameters.Paths[i]})
			out = append(out, Batch{ID: hash(data), Status: "pending", Targets: targets, Templates: []string{operation, input.Parameters.Paths[i]}})
		}
		return out
	}
	for _, target := range targets {
		out = append(out, Batch{ID: hash([]byte(target)), Status: "pending", Targets: []string{target}, Templates: []string{}})
	}
	return out
}
