package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

var providerHosts = map[string][]string{"crtsh": {"crt.sh"}, "certspotter": {"api.certspotter.com"}, "wayback": {"web.archive.org"}, "shodan-idb": {"internetdb.shodan.io"}}

func (b *HTTPBroker) providerHost(host string) bool {
	for _, provider := range b.policy.Job.Parameters.Providers {
		if slices.Contains(providerHosts[provider], strings.ToLower(host)) {
			return true
		}
	}
	return false
}
func (b *HTTPBroker) providerRequest(u *url.URL, method string) bool {
	if !ecosystemExternal(b.policy.Job.Capability) || method != "GET" || u.User != nil || u.Fragment != "" || !b.providerHost(u.Hostname()) || u.Port() != "" && u.Port() != "443" && u.Port() != "80" {
		return false
	}
	for _, target := range b.policy.Job.Targets {
		base, e := url.Parse(target)
		if e != nil {
			continue
		}
		host := base.Hostname()
		q := u.Query()
		switch u.Hostname() {
		case "crt.sh":
			if u.Path == "/" && (q.Get("q") == "%."+host || q.Get("q") == host || q.Get("CN") == host) && q.Get("output") == "json" && queryKeys(q, []string{"q", "CN", "output", "exclude"}) {
				return true
			}
		case "api.certspotter.com":
			if u.Path == "/v1/issuances" && q.Get("domain") == host && queryKeys(q, []string{"domain", "include_subdomains", "expand", "after", "match_wildcards"}) {
				return true
			}
		case "web.archive.org":
			if u.Path == "/cdx/search/cdx" && (q.Get("url") == host+"/*" || q.Get("url") == "*."+host+"/*" || q.Get("url") == host) && queryKeys(q, []string{"url", "output", "fl", "collapse", "filter", "matchType", "limit", "page", "from", "to", "showNumPages", "pageSize"}) {
				return true
			}
		case "internetdb.shodan.io":
			if net.ParseIP(host) != nil && u.Path == "/"+host && len(q) == 0 {
				return true
			}
		}
	}
	return false
}
func queryKeys(q url.Values, allowed []string) bool {
	for key, values := range q {
		if !slices.Contains(allowed, key) || len(values) > 8 {
			return false
		}
		for _, value := range values {
			if len(value) > 512 || strings.ContainsAny(value, "\r\n\x00") {
				return false
			}
		}
	}
	return true
}
func (b *HTTPBroker) fixtureHost(host string) bool {
	for _, origin := range b.policy.ProviderFixtures {
		u, e := url.Parse(origin)
		if e == nil && u.Hostname() == host {
			return true
		}
	}
	return false
}
func (b *HTTPBroker) rpcBudget(ctx context.Context) (func(), error) {
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
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case b.connections <- struct{}{}:
		return func() { <-b.connections }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (b *HTTPBroker) ecosystemRPC(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.IsAbs() || r.Host != "catbridge.internal" || !strings.HasPrefix(r.URL.Path, "/_catsuite/") {
		return false
	}
	switch r.URL.Path {
	case "/_catsuite/dns":
		b.rpcDNS(w, r)
	case "/_catsuite/tcp":
		b.rpcTCP(w, r)
	default:
		brokerError(w, "E_PERMISSION")
	}
	return true
}
func (b *HTTPBroker) rpcDNS(w http.ResponseWriter, r *http.Request) {
	var question struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1025))
	decoder.DisallowUnknownFields()
	if r.Method != "POST" || decoder.Decode(&question) != nil {
		brokerError(w, "E_PERMISSION")
		return
	}
	name, e := normalizeHost(strings.TrimSuffix(question.Name, "."))
	if e != nil {
		brokerError(w, "E_HOST")
		return
	}
	allowed := b.providerHost(name)
	for _, target := range b.policy.Job.Targets {
		u, err := url.Parse(target)
		if err == nil {
			copy := *u
			copy.Host = name
			if u.Port() != "" {
				copy.Host = net.JoinHostPort(name, u.Port())
			}
			if allows(b.policy.Job.Scope, copy.String()) && allows(b.policy.HostScope, copy.String()) {
				allowed = true
			}
		}
	}
	kinds := b.policy.Job.Parameters.RecordTypes
	if len(kinds) == 0 {
		kinds = []string{"A", "AAAA"}
	}
	if !allowed || !slices.Contains(kinds, question.Type) || ecosystemOffline(b.policy.Job.Capability) {
		brokerError(w, "E_PERMISSION")
		return
	}
	done, e := b.rpcBudget(r.Context())
	if e != nil {
		brokerError(w, e.Error())
		return
	}
	defer done()
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	records := []string{}
	if fixtures, ok := b.policy.DNSFixtures[name]; ok {
		records = fixtures[question.Type]
	} else {
		switch question.Type {
		case "A", "AAAA":
			family := "ip4"
			if question.Type == "AAAA" {
				family = "ip6"
			}
			ips, err := net.DefaultResolver.LookupIP(ctx, family, name)
			e = err
			for _, ip := range ips {
				records = append(records, ip.String())
			}
		case "CNAME":
			value, err := net.DefaultResolver.LookupCNAME(ctx, name)
			e = err
			if value != "" {
				records = append(records, strings.TrimSuffix(value, "."))
			}
		case "MX":
			values, err := net.DefaultResolver.LookupMX(ctx, name)
			e = err
			for _, value := range values {
				records = append(records, fmt.Sprintf("%d %s", value.Pref, strings.TrimSuffix(value.Host, ".")))
			}
		case "NS":
			values, err := net.DefaultResolver.LookupNS(ctx, name)
			e = err
			for _, value := range values {
				records = append(records, strings.TrimSuffix(value.Host, "."))
			}
		case "TXT":
			records, e = net.DefaultResolver.LookupTXT(ctx, name)
		}
	}
	if e != nil {
		records = []string{}
	}
	if len(records) > 50 {
		records = records[:50]
	}
	for _, record := range records {
		if len(record) > 4096 {
			brokerError(w, "E_SIZE")
			return
		}
	}
	response(w, 200, map[string]any{"name": name, "type": question.Type, "records": records, "ttlKnown": false, "dnssecVerified": false})
}
func (b *HTTPBroker) rpcTCP(w http.ResponseWriter, r *http.Request) {
	job := b.policy.Job
	port, e := strconv.Atoi(r.URL.Query().Get("port"))
	if r.Method != "GET" || !ecosystemTCP(job.Capability) || len(job.Targets) != 1 || e != nil || !slices.Contains(job.Parameters.Ports, port) || r.URL.Query().Get("host") != "" {
		brokerError(w, "E_PERMISSION")
		return
	}
	u, e := url.Parse(job.Targets[0])
	if e != nil {
		brokerError(w, "E_HOST")
		return
	}
	destination := *u
	destination.Host = joinHostPort(u.Hostname(), port)
	if !allows(job.Scope, destination.String()) || !allows(b.policy.HostScope, destination.String()) {
		brokerError(w, "E_HOST")
		return
	}
	done, e := b.rpcBudget(r.Context())
	if e != nil {
		brokerError(w, e.Error())
		return
	}
	defer done()
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	ips, e := net.DefaultResolver.LookupIPAddr(ctx, u.Hostname())
	if e != nil {
		brokerError(w, "E_HOST")
		return
	}
	values := []net.IP{}
	for _, ip := range ips {
		values = append(values, ip.IP)
	}
	if verifyResolution(job.Scope, u.Hostname(), values) != nil || verifyResolution(b.policy.HostScope, u.Hostname(), values) != nil {
		brokerError(w, "E_PRIVATE_DESTINATION")
		return
	}
	var remote net.Conn
	for _, ip := range values {
		remote, e = (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", joinHostPort(ip.String(), port))
		if e == nil {
			break
		}
	}
	if remote == nil {
		brokerError(w, "E_TCP")
		return
	}
	defer remote.Close()
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		brokerError(w, "E_HTTP")
		return
	}
	local, buffer, e := hijacker.Hijack()
	if e != nil {
		return
	}
	defer local.Close()
	deadline := time.Now().Add(time.Duration(job.Timeout) * time.Second)
	remote.SetDeadline(deadline)
	local.SetDeadline(deadline)
	buffer.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: catsuite-tcp\r\n\r\n")
	buffer.Flush()
	copied := make(chan struct{})
	go func() {
		io.Copy(remote, io.LimitReader(buffer.Reader, 2*1024*1024))
		if tcp, ok := remote.(*net.TCPConn); ok {
			tcp.CloseWrite()
		}
		close(copied)
	}()
	io.Copy(local, io.LimitReader(remote, 2*1024*1024))
	remote.Close()
	local.Close()
	<-copied
}
func openTaskTCP(ctx context.Context, port int) (net.Conn, *bufio.Reader, error) {
	conn, e := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", "/ipc/broker.sock")
	if e != nil {
		return nil, nil, e
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(conn, "GET /_catsuite/tcp?port=%d HTTP/1.1\r\nHost: catbridge.internal\r\n\r\n", port)
	reader := bufio.NewReader(conn)
	r, e := http.ReadResponse(reader, &http.Request{Method: "GET"})
	if e != nil || r.StatusCode != 101 {
		conn.Close()
		return nil, nil, errors.New("E_TCP")
	}
	conn.SetDeadline(time.Time{})
	return conn, reader, nil
}
