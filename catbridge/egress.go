package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

func guardedEgress(parent context.Context, input JobRequest) (string, func(), error) {
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return "", nil, e
	}
	ctx, cancel := context.WithCancel(parent)
	var mu sync.Mutex
	active := map[net.Conn]bool{}
	slots := make(chan struct{}, 2)
	dial := func(target *url.URL) (net.Conn, error) {
		allowed := false
		for _, original := range input.Targets {
			u, e := url.Parse(original)
			if e == nil && strings.EqualFold(u.Host, target.Host) && u.Scheme == target.Scheme {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, errors.New("E_HOST")
		}
		hostname, e := normalizeHost(target.Hostname())
		if e != nil {
			return nil, e
		}
		resolved, e := net.DefaultResolver.LookupIPAddr(ctx, hostname)
		if e != nil {
			return nil, errors.New("E_HOST")
		}
		ips := []net.IP{}
		for _, item := range resolved {
			ips = append(ips, item.IP)
		}
		if e = verifyResolution(input.Scope, hostname, ips); e != nil {
			return nil, e
		}
		port := target.Port()
		if port == "" {
			port = "443"
			if target.Scheme == "http" {
				port = "80"
			}
		}
		number, e := strconv.Atoi(port)
		if e != nil || number < 1 || number > 65535 {
			return nil, errors.New("E_HOST")
		}
		for _, ip := range ips {
			connection, e := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
			if e == nil {
				mu.Lock()
				active[connection] = true
				mu.Unlock()
				return connection, nil
			}
		}
		return nil, errors.New("E_HTTP")
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "E_QUEUE", 429)
			return
		}
		if r.Method == "CONNECT" {
			target, e := url.Parse("https://" + r.Host)
			if e != nil {
				http.Error(w, "E_HOST", 403)
				return
			}
			remote, e := dial(target)
			if e != nil {
				http.Error(w, "E_HOST", 403)
				return
			}
			defer func() { mu.Lock(); delete(active, remote); mu.Unlock(); remote.Close() }()
			connection, buffer, e := w.(http.Hijacker).Hijack()
			if e != nil {
				return
			}
			defer connection.Close()
			mu.Lock()
			active[connection] = true
			mu.Unlock()
			defer func() { mu.Lock(); delete(active, connection); mu.Unlock() }()
			if _, e = buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); e != nil {
				return
			}
			if buffer.Flush() != nil {
				return
			}
			done := make(chan struct{}, 1)
			go func() { io.Copy(remote, io.LimitReader(buffer, 8*1024*1024)); remote.Close(); done <- struct{}{} }()
			io.Copy(connection, io.LimitReader(remote, 8*1024*1024))
			connection.Close()
			remote.Close()
			<-done
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" || r.URL.Scheme != "http" || !allows(input.Scope, r.URL.String()) {
			http.Error(w, "E_HOST", 403)
			return
		}
		transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, ResponseHeaderTimeout: 10 * time.Second, DialContext: func(c context.Context, network, address string) (net.Conn, error) { return dial(r.URL) }}
		defer transport.CloseIdleConnections()
		outgoing := r.Clone(ctx)
		outgoing.RequestURI = ""
		outgoing.Header.Del("Proxy-Authorization")
		outgoing.Header.Del("Proxy-Connection")
		result, e := transport.RoundTrip(outgoing)
		if e != nil {
			http.Error(w, "E_HTTP", 502)
			return
		}
		defer result.Body.Close()
		for key, values := range result.Header {
			if !strings.EqualFold(key, "Connection") && !strings.EqualFold(key, "Transfer-Encoding") {
				w.Header()[key] = values
			}
		}
		w.WriteHeader(result.StatusCode)
		io.Copy(w, io.LimitReader(result.Body, 8*1024*1024))
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, MaxHeaderBytes: 32768}
	go server.Serve(listener)
	stop := func() {
		cancel()
		server.Close()
		mu.Lock()
		for connection := range active {
			connection.Close()
		}
		mu.Unlock()
	}
	go func() {
		<-ctx.Done()
		server.Close()
		mu.Lock()
		for connection := range active {
			connection.Close()
		}
		mu.Unlock()
	}()
	return "http://" + listener.Addr().String(), stop, nil
}
