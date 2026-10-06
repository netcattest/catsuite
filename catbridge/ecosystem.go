package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

var ecosystemVersions = map[string]string{"subfinder": "2.16.0", "dnsx": "1.3.1", "alterx": "0.1.0", "uncover": "1.2.1", "naabu": "2.6.1", "nmap": "7.991", "ffuf": "2.3.0", "gau": "2.2.4", "waybackurls": "0.1.0", "dalfox": "3.2.3", "gitleaks": "8.30.1", "trufflehog": "3.97.9", "amass": "5.1.1", "sqlmap": "1.10", "arjun": "2.2.7", "jwt_tool": "2.3.0", "testssl": "3.2.4", "nikto": "2.6.1", "semgrep": "1.179.0"}
var ecosystemTools = map[string][]string{
	"subfinder": {"assets.subdomains.discover"}, "amass": {"assets.subdomains.discover"}, "dnsx": {"dns.resolve", "dns.enumerate"}, "alterx": {"dns.permute"}, "uncover": {"assets.search"}, "gau": {"urls.history"}, "waybackurls": {"urls.history"}, "naabu": {"net.ports.discover"}, "nmap": {"net.ports.discover", "net.services.fingerprint"}, "ffuf": {"web.paths.fuzz", "http.parameters.fuzz", "web.vhosts.fuzz"}, "arjun": {"http.parameters.discover"}, "dalfox": {"web.xss.analyze"}, "sqlmap": {"api.sqli.validate"}, "jwt_tool": {"jwt.analyze"}, "testssl": {"tls.assess"}, "nikto": {"web.server.assess"}, "gitleaks": {"code.secrets.scan"}, "trufflehog": {"code.secrets.scan"}, "semgrep": {"code.sast.scan"},
}

func init() {
	for name, version := range ecosystemVersions {
		toolVersions[name] = version
	}
}
func supportsTool(tool, capability string) bool {
	return toolCapabilities[tool] == capability || slices.Contains(ecosystemTools[tool], capability)
}
func joinHostPort(host string, port int) string { return net.JoinHostPort(host, strconv.Itoa(port)) }
func parsePort(port string) int                 { value, _ := strconv.Atoi(port); return value }
func ecosystemOffline(capability string) bool {
	return slices.Contains([]string{"dns.permute", "jwt.analyze", "code.secrets.scan", "code.sast.scan"}, capability)
}
func ecosystemExternal(capability string) bool {
	return slices.Contains([]string{"assets.subdomains.discover", "urls.history", "assets.search"}, capability)
}
func ecosystemTCP(capability string) bool {
	return slices.Contains([]string{"net.ports.discover", "net.services.fingerprint", "tls.assess"}, capability)
}
func ecosystemActive(capability string) bool {
	return ecosystemTCP(capability) || slices.Contains([]string{"web.paths.fuzz", "http.parameters.fuzz", "web.vhosts.fuzz", "http.parameters.discover", "web.xss.analyze", "api.sqli.validate", "web.server.assess"}, capability)
}
func ecosystemResource(capability string) string {
	switch capability {
	case "web.paths.fuzz", "http.parameters.fuzz", "http.parameters.discover":
		return "wordlist"
	case "jwt.analyze":
		return "jwt"
	case "code.secrets.scan", "code.sast.scan":
		return "snapshot"
	}
	return ""
}
func ecosystemFields(capability string) []string {
	fields := []string{"profile", "methods", "requests", "maxResults"}
	if ecosystemExternal(capability) {
		fields = append(fields, "providers")
	}
	if ecosystemTCP(capability) {
		fields = append(fields, "ports")
	}
	if strings.HasPrefix(capability, "dns.") && capability != "dns.permute" {
		fields = append(fields, "recordTypes")
	}
	if capability == "dns.permute" {
		fields = append(fields, "patterns")
	}
	if slices.Contains([]string{"http.parameters.fuzz", "web.xss.analyze", "api.sqli.validate"}, capability) {
		fields = append(fields, "parameter")
	}
	if capability == "web.vhosts.fuzz" {
		fields = append(fields, "virtualHosts")
	}
	return fields
}
func (b *Bridge) validateEcosystem(input JobRequest) error {
	if !supportsTool(input.Tool, input.Capability) || !idPattern.MatchString(input.ID) || !regexp.MustCompile(`^[a-f0-9-]{36}$`).MatchString(input.Flow) || !idPattern.MatchString(input.Revision) || !idPattern.MatchString(input.Approval) || !regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`).MatchString(input.Node) || input.Lease != 15 || input.Rate < 1 || input.Rate > 5 || input.Timeout < 1 || input.Timeout > 300 || len(input.Targets) < 1 || len(input.Targets) > 25 || input.Parameters == nil {
		return errPermission
	}
	if !slices.Contains([]string{"PUBLIC", "PROTECTED", "SECRET"}, input.Protection) {
		return errPermission
	}
	image, ok := b.tools[input.Tool]
	if !ok {
		return errors.New("E_TOOL_UNAVAILABLE")
	}
	if b.runtimeError != "" {
		return errors.New(b.runtimeError)
	}
	if input.Contract != 2 || input.ExpectedImage != image.Image || input.ExpectedBinary != image.Binary || input.ExpectedBroker != b.brokerImage.Image {
		return errors.New("E_TOOL_CHANGED")
	}
	if len(input.TemplateIDs) != 0 || len(input.ExpectedTemplates) != 0 {
		return errPermission
	}
	if e := validateEcosystemHeaders(input); e != nil {
		return e
	}
	p := input.Parameters
	wire, _ := json.Marshal(p)
	var fields map[string]any
	json.Unmarshal(wire, &fields)
	for name := range fields {
		if !slices.Contains(ecosystemFields(input.Capability), name) {
			return errPermission
		}
	}
	if p.Requests < 1 || p.Requests > 500 || p.MaxResults < 1 || p.MaxResults > 1000 || len(p.Methods) != 1 || p.Methods[0] != "GET" {
		return errPermission
	}
	profile := "read-only"
	if ecosystemExternal(input.Capability) {
		profile = "external-approved"
	}
	if ecosystemActive(input.Capability) {
		profile = "active-approved"
	}
	if p.Profile != profile {
		return errors.New("E_DATA_APPROVAL")
	}
	resourceKind := ecosystemResource(input.Capability)
	if resourceKind == "" && input.Resource != "" || resourceKind != "" && !idPattern.MatchString(input.Resource) {
		return errors.New("E_RESOURCE")
	}
	if (input.Capability == "jwt.analyze" || input.Capability == "code.secrets.scan") && input.Protection != "SECRET" {
		return errors.New("E_CREDENTIAL_PROTECTION")
	}
	if len(p.Ports) > 32 || ecosystemTCP(input.Capability) && len(p.Ports) == 0 {
		return errors.New("E_LIMIT")
	}
	if ecosystemTCP(input.Capability) && len(input.Targets) != 1 || input.Capability == "tls.assess" && len(p.Ports) != 1 {
		return errors.New("E_LIMIT")
	}
	ports := map[int]bool{}
	for _, port := range p.Ports {
		if port < 1 || port > 65535 || ports[port] {
			return errPermission
		}
		ports[port] = true
	}
	if len(p.RecordTypes) > 6 || strings.HasPrefix(input.Capability, "dns.") && input.Capability != "dns.permute" && len(p.RecordTypes) == 0 {
		return errPermission
	}
	if !ecosystemUnique(p.RecordTypes) || !ecosystemUnique(p.Patterns) || !ecosystemUnique(p.Providers) {
		return errPermission
	}
	for _, kind := range p.RecordTypes {
		if !slices.Contains([]string{"A", "AAAA", "CNAME", "MX", "NS", "TXT"}, kind) {
			return errPermission
		}
	}
	if len(p.Patterns) > 3 {
		return errPermission
	}
	for _, pattern := range p.Patterns {
		if !slices.Contains([]string{"prefix", "suffix", "environment"}, pattern) {
			return errPermission
		}
	}
	if ecosystemExternal(input.Capability) {
		allowed := []string{"crtsh", "certspotter"}
		if input.Tool == "amass" {
			allowed = []string{"crtsh"}
		}
		if input.Capability == "urls.history" {
			allowed = []string{"wayback"}
		}
		if input.Capability == "assets.search" {
			allowed = []string{"shodan-idb"}
		}
		if len(p.Providers) < 1 || len(p.Providers) > len(allowed) {
			return errors.New("E_PROVIDER")
		}
		for _, provider := range p.Providers {
			if !slices.Contains(allowed, provider) {
				return errors.New("E_PROVIDER")
			}
		}
	}
	if p.Parameter != "" && !regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,63}$`).MatchString(p.Parameter) {
		return errPermission
	}
	if slices.Contains([]string{"http.parameters.fuzz", "web.xss.analyze", "api.sqli.validate"}, input.Capability) && p.Parameter == "" {
		return errPermission
	}
	if len(p.VirtualHosts) > 50 || input.Capability == "web.vhosts.fuzz" && len(p.VirtualHosts) == 0 {
		return errPermission
	}
	for _, target := range input.Targets {
		u, e := url.Parse(target)
		if e != nil || u.User != nil || u.Fragment != "" || len(target) > 8192 || !allows(input.Scope, target) || !allows(b.scope, target) {
			return errors.New("E_HOST")
		}
		if ecosystemExternal(input.Capability) && u.RawQuery != "" {
			return errors.New("E_DATA_APPROVAL")
		}
		if slices.Contains([]string{"api.sqli.validate", "web.xss.analyze"}, input.Capability) && !u.Query().Has(p.Parameter) {
			return errors.New("E_PARAMETER")
		}
		for _, port := range p.Ports {
			copy := *u
			copy.Host = joinHostPort(u.Hostname(), port)
			if !allows(input.Scope, copy.String()) || !allows(b.scope, copy.String()) {
				return errors.New("E_HOST")
			}
		}
		for _, hostname := range p.VirtualHosts {
			normalized, e := normalizeHost(hostname)
			if e != nil || normalized != hostname {
				return errors.New("E_HOST")
			}
			copy := *u
			copy.Host = hostname
			if u.Port() != "" {
				copy.Host = joinHostPort(hostname, parsePort(u.Port()))
			}
			if !allows(input.Scope, copy.String()) || !allows(b.scope, copy.String()) {
				return errors.New("E_HOST")
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, id := range []string{image.Image, b.brokerImage.Image} {
		value, e := b.dockerOutput(ctx, "image", "inspect", "--format", "{{.Id}}", id)
		if e != nil || strings.TrimSpace(string(value)) != id {
			return errors.New("E_TOOL_CHANGED")
		}
	}
	return nil
}
func validateEcosystemHeaders(input JobRequest) error {
	if len(input.Headers) > 16 || (len(input.Headers) == 0) != (input.DataProfile == "endpoints-only") || len(input.Headers) > 0 && input.DataProfile != "selected-headers" {
		return errors.New("E_DATA_APPROVAL")
	}
	if len(input.Headers) > 0 && (ecosystemOffline(input.Capability) || ecosystemExternal(input.Capability) || ecosystemTCP(input.Capability) || strings.HasPrefix(input.Capability, "dns.")) {
		return errors.New("E_DATA_APPROVAL")
	}
	bytes := 0
	seen := map[string]bool{}
	for _, header := range input.Headers {
		name := strings.ToLower(header.Name)
		bytes += len(header.Name) + len(header.Value)
		if !regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$").MatchString(header.Name) || strings.ContainsAny(header.Value, "\r\n\x00") || len(header.Value) > 8192 || bytes > 16384 || seen[name] || slices.Contains([]string{"host", "content-length", "transfer-encoding", "connection", "proxy-authorization", "proxy-connection", "upgrade", "te", "trailer"}, name) {
			return errPermission
		}
		seen[name] = true
		if slices.Contains([]string{"authorization", "cookie", "x-api-key", "api-key"}, name) && input.Protection != "SECRET" {
			return errors.New("E_CREDENTIAL_PROTECTION")
		}
	}
	return nil
}
func ecosystemParameterSchema(capability string) map[string]any {
	profile := "read-only"
	if ecosystemExternal(capability) {
		profile = "external-approved"
	}
	if ecosystemActive(capability) {
		profile = "active-approved"
	}
	props := map[string]any{"profile": map[string]any{"type": "string", "enum": []string{profile}}, "methods": map[string]any{"type": "array", "items": map[string]any{"enum": []string{"GET"}}, "maxItems": 1}, "requests": map[string]any{"type": "integer", "minimum": 1, "maximum": 500}, "maxResults": map[string]any{"type": "integer", "minimum": 1, "maximum": 1000}}
	for _, field := range ecosystemFields(capability) {
		if _, ok := props[field]; ok {
			continue
		}
		switch field {
		case "ports":
			props[field] = map[string]any{"type": "array", "maxItems": 32, "items": map[string]any{"type": "integer", "minimum": 1, "maximum": 65535}}
		case "parameter":
			props[field] = map[string]any{"type": "string", "maxLength": 64}
		default:
			props[field] = map[string]any{"type": "array", "maxItems": 50, "items": map[string]any{"type": "string"}}
		}
	}
	return map[string]any{"type": "object", "additionalProperties": false, "properties": props, "required": []string{"profile", "methods", "requests", "maxResults"}}
}

func ecosystemUnique(values []string) bool {
	seen := map[string]bool{}
	for _, v := range values {
		if seen[v] {
			return false
		}
		seen[v] = true
	}
	return true
}
