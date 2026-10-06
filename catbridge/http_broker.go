package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

type BrokerPolicy struct {
	Job              JobRequest                     `json:"job"`
	HostScope        []string                       `json:"hostScope"`
	CA               string                         `json:"upstreamCA,omitempty"`
	ProviderFixtures map[string]string              `json:"providerFixtures,omitempty"`
	DNSFixtures      map[string]map[string][]string `json:"dnsFixtures,omitempty"`
}
type HTTPBroker struct {
	policy       BrokerPolicy
	root         *x509.Certificate
	key          *ecdsa.PrivateKey
	pem          []byte
	transport    *http.Transport
	mu           sync.Mutex
	requests     int
	next         time.Time
	pages        map[string]bool
	fingerprints map[string]string
	discoveries  map[string]json.RawMessage
	connections  chan struct{}
}

func newHTTPBroker(policy BrokerPolicy) (*HTTPBroker, error) {
	if policy.Job.Parameters == nil || policy.Job.Parameters.Requests < 1 || policy.Job.Parameters.Requests > 1000 || policy.Job.Rate < 1 || policy.Job.Rate > 5 || len(policy.Job.Parameters.Methods) == 0 || !supportsTool(policy.Job.Tool, policy.Job.Capability) {
		return nil, errPermission
	}
	for _, target := range policy.Job.Targets {
		if !allows(policy.Job.Scope, target) || !allows(policy.HostScope, target) {
			return nil, errors.New("E_HOST")
		}
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, e
	}
	cert := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "CatBridge task " + policy.Job.ID}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	wire, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		return nil, e
	}
	root, e := x509.ParseCertificate(wire)
	if e != nil {
		return nil, e
	}
	broker := &HTTPBroker{policy: policy, root: root, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: wire}), pages: map[string]bool{}, discoveries: map[string]json.RawMessage{}, fingerprints: map[string]string{}, connections: make(chan struct{}, 2)}
	pool, e := x509.SystemCertPool()
	if e != nil {
		pool = x509.NewCertPool()
	}
	if policy.CA != "" && !pool.AppendCertsFromPEM([]byte(policy.CA)) {
		return nil, errors.New("E_TLS")
	}
	broker.transport = &http.Transport{Proxy: nil, DisableCompression: true, MaxConnsPerHost: 2, MaxIdleConns: 2, ResponseHeaderTimeout: 10 * time.Second, TLSHandshakeTimeout: 10 * time.Second, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		hostname, port, e := net.SplitHostPort(address)
		if e != nil {
			return nil, errors.New("E_HOST")
		}
		hostname, e = normalizeHost(hostname)
		if e != nil {
			return nil, e
		}
		ips, e := net.DefaultResolver.LookupIPAddr(ctx, hostname)
		if e != nil {
			return nil, errors.New("E_HOST")
		}
		values := []net.IP{}
		for _, ip := range ips {
			values = append(values, ip.IP)
		}
		provider := broker.providerHost(hostname)
		fixture := broker.fixtureHost(hostname)
		if provider {
			for _, ip := range values {
				if privateAddress(ip) {
					return nil, errors.New("E_PRIVATE_DESTINATION")
				}
			}
		}
		if !provider && !fixture && (verifyResolution(policy.Job.Scope, hostname, values) != nil || verifyResolution(policy.HostScope, hostname, values) != nil) {
			return nil, errors.New("E_PRIVATE_DESTINATION")
		}
		for _, ip := range values {
			conn, e := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
			if e == nil {
				return conn, nil
			}
		}
		return nil, errors.New("E_HTTP")
	}}
	return broker, nil
}
func (b *HTTPBroker) certificate(host string) (tls.Certificate, error) {
	host, _, e := net.SplitHostPort(host)
	if e != nil {
		return tls.Certificate{}, errors.New("E_HOST")
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return tls.Certificate{}, e
	}
	leaf := &x509.Certificate{SerialNumber: new(big.Int).Set(serial()), Subject: pkix.Name{CommonName: host}, NotBefore: b.root.NotBefore, NotAfter: b.root.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if ip := net.ParseIP(host); ip != nil {
		leaf.IPAddresses = []net.IP{ip}
	} else {
		leaf.DNSNames = []string{host}
	}
	wire, e := x509.CreateCertificate(rand.Reader, leaf, b.root, &key.PublicKey, b.key)
	if e != nil {
		return tls.Certificate{}, e
	}
	return tls.Certificate{Certificate: [][]byte{wire, b.root.Raw}, PrivateKey: key}, nil
}
func canonicalOrigin(u *url.URL) string {
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return u.Scheme + "://" + net.JoinHostPort(strings.ToLower(u.Hostname()), port)
}
func (b *HTTPBroker) permits(u *url.URL, method string) bool {
	if ecosystemOffline(b.policy.Job.Capability) || ecosystemTCP(b.policy.Job.Capability) {
		return false
	}
	if ecosystemExternal(b.policy.Job.Capability) {
		return b.providerRequest(u, method)
	}
	if u.User != nil || u.Fragment != "" || !allows(b.policy.Job.Scope, u.String()) || !allows(b.policy.HostScope, u.String()) || strings.ContainsAny(u.Path, "\\\x00") || strings.Contains(strings.ToLower(u.RawPath), "%25") || path.Clean(u.Path) != strings.TrimSuffix(u.Path, "/") && u.Path != "/" {
		return false
	}
	allowedMethod := false
	for _, m := range b.policy.Job.Parameters.Methods {
		if method == m {
			allowedMethod = true
		}
	}
	if !allowedMethod {
		return false
	}
	same := false
	for _, target := range b.policy.Job.Targets {
		base, e := url.Parse(target)
		if e == nil && canonicalOrigin(u) == canonicalOrigin(base) {
			same = true
			break
		}
	}
	if !same {
		return false
	}
	if _, ok := ecosystemVersions[b.policy.Job.Tool]; ok {
		base, _ := url.Parse(b.policy.Job.Targets[0])
		if b.policy.Job.Capability == "web.paths.fuzz" {
			return strings.HasPrefix(u.Path, strings.TrimSuffix(base.Path, "/")+"/")
		}
		if b.policy.Job.Capability == "web.server.assess" {
			return true
		}
		if u.Path != base.Path {
			return false
		}
		for key, values := range u.Query() {
			if key == b.policy.Job.Parameters.Parameter || b.policy.Job.Capability == "http.parameters.discover" {
				continue
			}
			if strings.Join(values, "\x00") != strings.Join(base.Query()[key], "\x00") {
				return false
			}
		}
		return true
	}
	if b.policy.Job.Tool == "httpx" {
		for _, target := range b.policy.Job.Targets {
			base, e := url.Parse(target)
			if e == nil && u.Path == base.Path && u.RawQuery == base.RawQuery {
				return true
			}
		}
		return false
	}
	if b.policy.Job.Tool == "schemathesis" {
		base, _ := url.Parse(b.policy.Job.Targets[0])
		for i, p := range b.policy.Job.Parameters.Paths {
			parts := strings.SplitN(b.policy.Job.Parameters.Operations[i], " ", 2)
			if len(parts) != 2 || parts[0] != method {
				continue
			}
			pattern := regexp.QuoteMeta(strings.TrimSuffix(base.Path, "/") + p)
			pattern = regexp.MustCompile(`\\\{[^}]+\\\}`).ReplaceAllString(pattern, "[^/]+")
			if regexp.MustCompile("^" + pattern + "$").MatchString(u.Path) {
				return true
			}
		}
		return false
	}
	return true
}
func (b *HTTPBroker) forward(r *http.Request, u *url.URL) (*http.Response, error) {
	if !b.permits(u, r.Method) {
		return nil, errors.New("E_PERMISSION")
	}
	if r.ContentLength > 1024*1024 {
		return nil, errors.New("E_SIZE")
	}
	b.mu.Lock()
	if b.requests >= b.policy.Job.Parameters.Requests {
		b.mu.Unlock()
		return nil, errors.New("E_REQUEST_BUDGET")
	}
	delay := time.Until(b.next)
	if delay < 0 {
		delay = 0
	}
	b.next = time.Now().Add(delay + time.Second/time.Duration(b.policy.Job.Rate))
	b.requests++
	b.mu.Unlock()
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-r.Context().Done():
		return nil, r.Context().Err()
	}
	select {
	case b.connections <- struct{}{}:
		defer func() { <-b.connections }()
	case <-r.Context().Done():
		return nil, r.Context().Err()
	}
	copy := r.Clone(r.Context())
	copy.URL = u
	if ecosystemExternal(b.policy.Job.Capability) {
		rewritten := *u
		rewritten.Scheme = "https"
		if origin := b.policy.ProviderFixtures[u.Hostname()]; origin != "" {
			fixture, _ := url.Parse(origin)
			rewritten.Scheme = fixture.Scheme
			rewritten.Host = fixture.Host
		}
		copy.URL = &rewritten
	}
	copy.RequestURI = ""
	copy.Host = u.Host
	if b.policy.Job.Capability == "web.vhosts.fuzz" {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		if !slices.Contains(b.policy.Job.Parameters.VirtualHosts, host) {
			return nil, errors.New("E_HOST")
		}
		copy.Host = r.Host
	}
	copy.Header = r.Header.Clone()
	copy.Close = false
	for _, name := range []string{"Connection", "Proxy-Connection", "Proxy-Authorization", "Upgrade", "Te", "Trailer", "Transfer-Encoding", "Cookie", "Authorization", "X-Api-Key", "Api-Key"} {
		copy.Header.Del(name)
	}
	for _, h := range b.policy.Job.Headers {
		copy.Header.Set(h.Name, h.Value)
	}
	if r.Body != nil {
		data, e := io.ReadAll(io.LimitReader(r.Body, 1024*1024+1))
		if e != nil || len(data) > 1024*1024 {
			return nil, errors.New("E_SIZE")
		}
		copy.Body = io.NopCloser(strings.NewReader(string(data)))
		copy.ContentLength = int64(len(data))
		copy.TransferEncoding = nil
	}
	response, e := b.transport.RoundTrip(copy)
	if e != nil {
		return nil, errors.New("E_TLS_HTTP")
	}
	if response.TLS != nil && len(response.TLS.PeerCertificates) > 0 {
		b.mu.Lock()
		b.fingerprints[canonicalOrigin(u)] = hash(response.TLS.PeerCertificates[0].Raw)
		b.mu.Unlock()
	}
	if b.policy.Job.Tool == "katana" && strings.Contains(response.Header.Get("Content-Type"), "text/html") {
		b.mu.Lock()
		b.pages[u.String()] = true
		over := len(b.pages) > b.policy.Job.Parameters.Pages
		b.mu.Unlock()
		if over {
			response.Body.Close()
			return nil, errors.New("E_PAGE_BUDGET")
		}
	}
	body, e := io.ReadAll(io.LimitReader(response.Body, 2*1024*1024+1))
	response.Body.Close()
	if e != nil || len(body) > 2*1024*1024 {
		return nil, errors.New("E_SIZE")
	}
	if b.policy.Job.Tool == "katana" && (strings.Contains(response.Header.Get("Content-Type"), "javascript") || strings.HasSuffix(u.Path, ".js")) {
		b.discoverJavaScript(u, body)
	}
	response.Body = io.NopCloser(strings.NewReader(string(body)))
	response.ContentLength = int64(len(body))
	response.TransferEncoding = nil
	return response, nil
}
func brokerError(w http.ResponseWriter, code string) {
	w.Header().Set("X-CatBridge-Blocked", "true")
	http.Error(w, code, http.StatusForbidden)
}
func (b *HTTPBroker) discoverJavaScript(source *url.URL, body []byte) {
	pattern := regexp.MustCompile(`["'](https?://[^"'\s]+|/[a-zA-Z0-9_][^"'\s]*)["']`)
	for _, match := range pattern.FindAllSubmatchIndex(body, 100) {
		candidate, e := url.Parse(string(body[match[2]:match[3]]))
		if e != nil || candidate.User != nil || candidate.Fragment != "" {
			continue
		}
		candidate = source.ResolveReference(candidate)
		if candidate.Scheme != "http" && candidate.Scheme != "https" {
			continue
		}
		parameters := []string{}
		for name := range candidate.Query() {
			parameters = append(parameters, name)
		}
		sort.Strings(parameters)
		value := map[string]any{"kind": "endpoint", "url": sanitizeURL(candidate.String()), "method": "GET", "fetched": false, "confidence": "hypothesis", "source": sanitizeURL(source.String()), "tag": "javascript-string", "reference": map[string]any{"sha256": hash(body), "byteOffset": match[2]}, "parameters": parameters}
		wire, _ := json.Marshal(cleanToolValue(value, b.policy.Job, 0))
		b.mu.Lock()
		if len(b.discoveries) < 500 {
			b.discoveries[hash(wire)] = wire
		}
		b.mu.Unlock()
	}
}
func (b *HTTPBroker) discovered() []json.RawMessage {
	b.mu.Lock()
	defer b.mu.Unlock()
	keys := []string{}
	for key := range b.discoveries {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	values := []json.RawMessage{}
	for _, key := range keys {
		values = append(values, b.discoveries[key])
	}
	return values
}
func (b *HTTPBroker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if b.ecosystemRPC(w, r) {
		return
	}
	if r.Method == "CONNECT" {
		b.tunnel(w, r)
		return
	}
	if r.URL.Scheme != "http" {
		brokerError(w, "E_PERMISSION")
		return
	}
	response, e := b.forward(r, r.URL)
	if e != nil {
		brokerError(w, e.Error())
		return
	}
	defer response.Body.Close()
	for name, values := range response.Header {
		for _, v := range values {
			w.Header().Add(name, v)
		}
	}
	w.WriteHeader(response.StatusCode)
	io.Copy(w, response.Body)
}
func (b *HTTPBroker) tunnel(w http.ResponseWriter, r *http.Request) {
	target, e := url.Parse("https://" + r.Host)
	if e != nil {
		brokerError(w, "E_HOST")
		return
	}
	allowed := false
	if b.providerHost(target.Hostname()) {
		allowed = true
	}
	for _, input := range b.policy.Job.Targets {
		u, _ := url.Parse(input)
		if u != nil && canonicalOrigin(u) == canonicalOrigin(target) {
			allowed = true
		}
	}
	if !allowed {
		brokerError(w, "E_HOST")
		return
	}
	cert, e := b.certificate(r.Host)
	if e != nil {
		brokerError(w, "E_TLS")
		return
	}
	h, ok := w.(http.Hijacker)
	if !ok {
		brokerError(w, "E_HTTP")
		return
	}
	raw, buf, e := h.Hijack()
	if e != nil {
		return
	}
	defer raw.Close()
	buf.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	buf.Flush()
	raw.SetDeadline(time.Now().Add(30 * time.Second))
	conn := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
	if conn.Handshake() != nil {
		return
	}
	reader := bufio.NewReader(conn)
	for {
		raw.SetDeadline(time.Now().Add(30 * time.Second))
		request, e := http.ReadRequest(reader)
		if e != nil {
			return
		}
		request = request.WithContext(r.Context())
		request.URL.Scheme = "https"
		request.URL.Host = r.Host
		if request.Host != r.Host && request.Host != target.Hostname() {
			return
		}
		response, e := b.forward(request, request.URL)
		if e != nil {
			response = &http.Response{StatusCode: 403, Status: "403 Forbidden", ProtoMajor: 1, ProtoMinor: 1, Header: http.Header{"X-Catbridge-Blocked": []string{"true"}}, Body: io.NopCloser(strings.NewReader(e.Error())), ContentLength: int64(len(e.Error()))}
		}
		response.Close = request.Close
		e = response.Write(conn)
		response.Body.Close()
		if e != nil || request.Close {
			return
		}
	}
}
func (b *HTTPBroker) summary() json.RawMessage {
	b.mu.Lock()
	defer b.mu.Unlock()
	data, _ := json.Marshal(map[string]any{"kind": "broker_summary", "url": b.policy.Job.Targets[0], "requests": b.requests, "pages": len(b.pages), "upstreamTLS": b.fingerprints})
	return data
}
