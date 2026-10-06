package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

type ecosystemCommand struct {
	Binary      string
	Entry       string
	Args        []string
	Input       string
	Report      string
	Format      string
	FindingExit bool
	Files       map[string][]byte
}

func ecosystemEntry(tool string) string {
	switch tool {
	case "nmap":
		return "/usr/local/bin/nmap"
	case "semgrep":
		return "/opt/venv/bin/semgrep"
	case "sqlmap":
		return "/opt/tools/sqlmap/sqlmap.py"
	case "arjun":
		return "/opt/tools/arjun/arjun/__main__.py"
	case "jwt_tool":
		return "/opt/tools/jwt_tool/jwt_tool.py"
	case "testssl":
		return "/opt/tools/testssl/testssl.sh"
	case "nikto":
		return "/opt/tools/nikto/program/nikto.pl"
	}
	return "/opt/tools/" + tool
}
func prepareEcosystemResource(input RunnerInput) (EcosystemResource, error) {
	kind := ecosystemResource(input.Policy.Job.Capability)
	if kind == "" {
		return EcosystemResource{}, nil
	}
	data, e := base64.StdEncoding.Strict().DecodeString(input.Schema)
	if e != nil {
		return EcosystemResource{}, errors.New("E_RESOURCE")
	}
	resource, e := ecosystemResourceDocument(data, kind)
	if e != nil {
		return resource, e
	}
	if kind == "wordlist" {
		e = os.WriteFile("/tmp/words.txt", []byte(strings.Join(resource.Words, "\n")+"\n"), 0600)
	}
	if kind == "snapshot" {
		for _, file := range resource.Files {
			location := filepath.Join("/tmp/snapshot", filepath.FromSlash(file.Path))
			if e = os.MkdirAll(filepath.Dir(location), 0700); e != nil {
				break
			}
			decoded, _ := base64.StdEncoding.Strict().DecodeString(file.Data)
			if e = os.WriteFile(location, decoded, 0600); e != nil {
				break
			}
		}
	}
	return resource, e
}
func taskForwarders(ctx context.Context, ports []int) (map[int]int, func(), error) {
	mapped := map[int]int{}
	listeners := []net.Listener{}
	closeAll := func() {
		for _, listener := range listeners {
			listener.Close()
		}
	}
	for _, port := range ports {
		probe, _, e := openTaskTCP(ctx, port)
		if e != nil {
			continue
		}
		probe.Close()
		listener, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			closeAll()
			return nil, nil, e
		}
		listeners = append(listeners, listener)
		mapped[listener.Addr().(*net.TCPAddr).Port] = port
		go func(listener net.Listener, port int) {
			for {
				local, e := listener.Accept()
				if e != nil {
					return
				}
				go func() {
					defer local.Close()
					remote, reader, e := openTaskTCP(ctx, port)
					if e != nil {
						return
					}
					defer remote.Close()
					stop := context.AfterFunc(ctx, func() { local.Close(); remote.Close() })
					defer stop()
					done := make(chan struct{})
					go func() {
						io.Copy(remote, io.LimitReader(local, 2*1024*1024))
						if socket, ok := remote.(*net.UnixConn); ok {
							socket.CloseWrite()
						}
						close(done)
					}()
					io.Copy(local, io.LimitReader(reader, 2*1024*1024))
					local.Close()
					remote.Close()
					<-done
				}()
			}
		}(listener, port)
	}
	return mapped, closeAll, nil
}
func ecosystemCommandFor(job JobRequest, target string, proxy string, resource EcosystemResource, ports map[int]int) (ecosystemCommand, error) {
	p := job.Parameters
	u, e := url.Parse(target)
	if e != nil {
		return ecosystemCommand{}, errors.New("E_HOST")
	}
	host := u.Hostname()
	rate := fmt.Sprint(job.Rate)
	budget := fmt.Sprint(p.MaxResults)
	c := ecosystemCommand{Binary: ecosystemEntry(job.Tool), Entry: ecosystemEntry(job.Tool), Format: "lines", Files: map[string][]byte{}}
	domains := []string{}
	for _, target := range job.Targets {
		u, _ := url.Parse(target)
		domains = append(domains, u.Hostname())
	}
	c.Input = strings.Join(domains, "\n") + "\n"
	switch job.Tool {
	case "subfinder":
		c.Args = []string{"-d", host, "-s", strings.Join(p.Providers, ","), "-oJ", "-cs", "-silent", "-duc", "-timeout", "10", "-max-time", "2", "-rl", rate, "-proxy", proxy}
	case "amass":
		c.Args = []string{"enum", "-passive", "-d", host, "-include", "crt.sh", "-timeout", "1", "-dir", "/tmp/config/amass", "-nocolor", "-rigid"}
	case "dnsx":
		c.Files["/tmp/hosts.txt"] = []byte(c.Input)
		c.Args = []string{"-l", "/tmp/hosts.txt", "-r", "127.0.0.1:53", "-json", "-silent", "-duc", "-retry", "0", "-rl", rate, "-t", "2"}
		for _, kind := range p.RecordTypes {
			c.Args = append(c.Args, "-"+strings.ToLower(kind))
		}
	case "alterx":
		c.Files["/tmp/hosts.txt"] = []byte(c.Input)
		c.Files["/tmp/prefix.txt"] = []byte("dev\nstaging\ntest\napi\n")
		patterns := []string{}
		for _, pattern := range p.Patterns {
			switch pattern {
			case "prefix":
				patterns = append(patterns, "{{word}}.{{sub}}.{{root}}")
			case "suffix":
				patterns = append(patterns, "{{sub}}-{{word}}.{{root}}")
			case "environment":
				patterns = append(patterns, "{{word}}-{{sub}}.{{root}}")
			}
		}
		if len(patterns) == 0 {
			patterns = []string{"{{word}}.{{sub}}.{{root}}"}
		}
		c.Args = []string{"-l", "/tmp/hosts.txt", "-p", strings.Join(patterns, ","), "-pp", "word=/tmp/prefix.txt", "-limit", budget, "-silent", "-duc", "-ms", "1mb"}
	case "uncover":
		c.Args = []string{"-e", "shodan-idb", "-q", host, "-json", "-silent", "-limit", budget, "-retry", "0", "-rl", rate, "-proxy", proxy, "-timeout", "10"}
	case "gau":
		c.Args = []string{"--providers", "wayback", "--json", "--threads", "1", "--retries", "0", "--timeout", "10", "--proxy", proxy}
	case "waybackurls":
		c.Args = []string{"-no-subs"}
	case "naabu", "nmap":
		selected := []string{}
		for port := range ports {
			selected = append(selected, fmt.Sprint(port))
		}
		sort.Strings(selected)
		if len(selected) == 0 {
			return c, nil
		}
		if job.Tool == "naabu" {
			c.Args = []string{"-host", "127.0.0.1", "-p", strings.Join(selected, ","), "-s", "c", "-Pn", "-json", "-silent", "-duc", "-rate", rate, "-c", "2", "-retries", "1", "-timeout", "1000", "-warm-up-time", "0", "-no-stdin"}
		} else {
			c.Args = []string{"-sT", "-Pn", "-n", "--unprivileged", "--max-retries", "0", "--host-timeout", fmt.Sprint(job.Timeout) + "s", "--max-parallelism", "2", "-oX", "-", "-p", strings.Join(selected, ","), "127.0.0.1"}
			c.Format = "xml"
			if job.Capability == "net.services.fingerprint" {
				c.Args = append(c.Args, "-sV", "--version-light")
			}
		}
	case "ffuf":
		value := *u
		switch job.Capability {
		case "web.paths.fuzz":
			value.Path = strings.TrimSuffix(value.Path, "/") + "/FUZZ"
		case "http.parameters.fuzz":
			q := value.Query()
			q.Set(p.Parameter, "FUZZ")
			value.RawQuery = q.Encode()
		case "web.vhosts.fuzz":
			c.Files["/tmp/words.txt"] = []byte(strings.Join(p.VirtualHosts, "\n") + "\n")
		}
		c.Args = []string{"-u", value.String(), "-w", "/tmp/words.txt", "-x", proxy, "-rate", rate, "-t", "2", "-timeout", "10", "-noninteractive", "-of", "json", "-o", "/tmp/ffuf.json", "-mc", "all", "-s"}
		if job.Capability == "web.vhosts.fuzz" {
			c.Args = append(c.Args, "-H", "Host: FUZZ")
		}
		c.Report = "/tmp/ffuf.json"
		c.Format = "json"
	case "arjun":
		c.Binary = "/opt/venv/bin/python"
		c.Args = []string{c.Entry, "-u", target, "-m", "GET", "-w", "/tmp/words.txt", "-t", "1", "-T", "5", "-c", "2", "-d", "0.2", "--disable-redirects", "-oJ", "/tmp/arjun.json", "-q"}
		c.Report = "/tmp/arjun.json"
		c.Format = "json"
	case "dalfox":
		c.Args = []string{"scan", target, "-p", p.Parameter + ":query", "-X", "GET", "--format", "json", "--output", "/tmp/dalfox.json", "--no-color", "--silence", "--skip-discovery", "--skip-mining", "--skip-reflection-header", "--skip-reflection-cookie", "--skip-reflection-path", "--skip-ast-analysis", "--skip-waf-probe", "--waf-bypass", "off", "--workers", "2", "--max-concurrent-targets", "1", "--max-payloads-per-param", "10", "--timeout", "5", "--scan-timeout", fmt.Sprint(job.Timeout), "--rate-limit", rate, "--retries", "0", "--proxy", proxy, "--insecure=true"}
		c.Report = "/tmp/dalfox.json"
		c.Format = "json"
		c.FindingExit = true
	case "sqlmap":
		c.Binary = "/opt/venv/bin/python"
		c.Files["/tmp/sqlmap-targets.txt"] = []byte(target + "\n")
		c.Args = []string{c.Entry, "-m", "/tmp/sqlmap-targets.txt", "-p", p.Parameter, "--batch", "--level=1", "--risk=1", "--technique=BE", "--threads=1", "--timeout=5", "--retries=0", "--proxy=" + proxy, "--ignore-redirects", "--disable-coloring", "--output-dir=/tmp/sqlmap", "--results-file=/tmp/sqlmap-results.csv"}
		c.Report = "/tmp/sqlmap-results.csv"
		c.Format = "sqlmap"
	case "jwt_tool":
		c.Binary = "/opt/venv/bin/python"
		c.Args = []string{c.Entry, resource.Token}
		c.Format = "jwt"
	case "testssl":
		localPort := 0
		for local, remote := range ports {
			if remote == p.Ports[0] {
				localPort = local
			}
		}
		if localPort == 0 {
			return c, nil
		}
		c.Binary = "/bin/bash"
		c.Args = []string{c.Entry, "--quiet", "--color", "0", "--openssl", "/usr/bin/openssl", "--ip", "127.0.0.1", "--warnings", "off", "--protocols", "--server-defaults", "--jsonfile", "/tmp/testssl.json", net.JoinHostPort(host, fmt.Sprint(localPort))}
		c.Report = "/tmp/testssl.json"
		c.Format = "json"
		c.FindingExit = true
	case "nikto":
		c.Binary = "/usr/bin/perl"
		c.Args = []string{c.Entry, "-h", target, "-useproxy", proxy, "-Tuning", "123b", "-nointeractive", "-ask", "no", "-timeout", "5", "-maxtime", fmt.Sprint(job.Timeout) + "s", "-Format", "json", "-output", "/tmp/nikto.json"}
		c.Report = "/tmp/nikto.json"
		c.Format = "json"
		c.FindingExit = true
	case "gitleaks":
		c.Files["/tmp/gitleaks.toml"] = []byte("[extend]\nuseDefault = true\n")
		c.Args = []string{"dir", "/tmp/snapshot", "--config", "/tmp/gitleaks.toml", "--redact=100", "--no-banner", "--no-color", "--ignore-gitleaks-allow", "--max-archive-depth=0", "--max-decode-depth=0", "--max-target-megabytes=1", "--timeout", fmt.Sprint(job.Timeout), "--report-format=json", "--report-path=/tmp/gitleaks.json", "--exit-code=0"}
		c.Report = "/tmp/gitleaks.json"
		c.Format = "json"
	case "trufflehog":
		c.Args = []string{"filesystem", "/tmp/snapshot", "--no-verification", "--no-update", "--json", "--concurrency=2", "--max-decode-depth=1", "--force-skip-binaries", "--force-skip-archives", "--log-level=-1", "--no-ignore-tag"}
	case "semgrep":
		c.Args = []string{"scan", "--config", "/opt/rules/catsuite.yml", "--json", "--metrics", "off", "--disable-version-check", "--no-git-ignore", "--jobs", "1", "--timeout", "5", "--max-target-bytes", "262144", "/tmp/snapshot"}
		c.Format = "json"
	default:
		return c, errPermission
	}
	return c, nil
}
func runEcosystem(ctx context.Context, input RunnerInput, proxy, rootPath string) error {
	job := input.Policy.Job
	resource, e := prepareEcosystemResource(input)
	if e != nil {
		return e
	}
	digest, e := fileHash(ecosystemEntry(job.Tool))
	if e != nil || digest != job.ExpectedBinary {
		return errors.New("E_TOOL_CHANGED")
	}
	if e = os.MkdirAll("/tmp/config", 0700); e != nil {
		return errors.New("E_RESOURCE")
	}
	if job.Tool == "amass" {
		if e = os.MkdirAll("/tmp/amass-logs", 0700); e != nil {
			return errors.New("E_RESOURCE")
		}
		engine := exec.CommandContext(ctx, ecosystemEntry("amass"), "engine", "-silent", "-log-dir", "/tmp/amass-logs")
		engine.Env = append(ecosystemEnvironment(proxy, rootPath), "NO_PROXY=127.0.0.1,localhost")
		engine.Stdout = io.Discard
		engine.Stderr = io.Discard
		if engine.Start() != nil {
			return errors.New("E_EXECUTOR")
		}
		defer func() { engine.Process.Kill(); engine.Wait() }()
		ready := false
		for i := 0; i < 100; i++ {
			connection, err := net.DialTimeout("tcp", "127.0.0.1:4000", 100*time.Millisecond)
			if err == nil {
				connection.Close()
				ready = true
				break
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
		if !ready {
			return errors.New("E_EXECUTOR")
		}
	}
	var ports map[int]int
	closePorts := func() {}
	if ecosystemTCP(job.Capability) {
		ports, closePorts, e = taskForwarders(ctx, job.Parameters.Ports)
		if e != nil {
			return e
		}
		defer closePorts()
	}
	stopDNS, e := taskDNS(ctx)
	if e != nil {
		return errors.New("E_DNS_GATEWAY")
	}
	defer stopDNS()
	emitted := 0
	seen := map[string]bool{}
	emit := func(record map[string]any) error {
		if record == nil {
			return nil
		}
		record["capability"] = job.Capability
		record["tool"] = job.Tool
		record["version"] = ecosystemVersions[job.Tool]
		record["confidence"] = recordConfidence(record)
		record["flow"] = job.Flow
		record["revision"] = job.Revision
		record["step"] = job.Node
		record["protection"] = job.Protection
		data, _ := json.Marshal(cleanToolValue(record, job, 0))
		if len(data) > 128*1024 {
			return errors.New("E_SIZE")
		}
		id := hash(data)
		if seen[id] || emitted >= job.Parameters.MaxResults {
			return nil
		}
		seen[id] = true
		emitted++
		fmt.Println(string(data))
		return nil
	}
	targets := job.Targets
	if ecosystemOffline(job.Capability) || job.Tool == "dnsx" || job.Tool == "gau" || job.Tool == "waybackurls" {
		targets = targets[:1]
	}
	for _, target := range targets {
		command, e := ecosystemCommandFor(job, target, proxy, resource, ports)
		if e != nil {
			return e
		}
		if ecosystemTCP(job.Capability) && len(ports) == 0 {
			continue
		}
		for path, contents := range command.Files {
			if !slices.Contains([]string{"/tmp/hosts.txt", "/tmp/prefix.txt", "/tmp/words.txt", "/tmp/sqlmap-targets.txt", "/tmp/gitleaks.toml"}, path) || os.WriteFile(path, contents, 0600) != nil {
				return errors.New("E_RESOURCE")
			}
		}
		task := exec.CommandContext(ctx, command.Binary, command.Args...)
		task.Dir = "/tmp"
		task.Stdin = strings.NewReader(command.Input)
		task.Env = ecosystemEnvironment(proxy, rootPath)
		if job.Tool == "amass" {
			task.Env = append(task.Env, "NO_PROXY=127.0.0.1,localhost")
		}
		task.Stderr = io.Discard
		pipe, e := task.StdoutPipe()
		if e != nil {
			return e
		}
		if e = task.Start(); e != nil {
			return errors.New("E_EXECUTOR")
		}
		raw, e := io.ReadAll(io.LimitReader(pipe, 8*1024*1024+1))
		if e != nil || len(raw) > 8*1024*1024 {
			task.Process.Kill()
			task.Wait()
			return errors.New("E_SIZE")
		}
		runErr := task.Wait()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if runErr != nil {
			exit, ok := runErr.(*exec.ExitError)
			if !ok || !command.FindingExit || exit.ExitCode() != 1 {
				return errors.New("E_EXECUTOR")
			}
		}
		if command.Report != "" {
			raw, e = limitedFile(command.Report, 8*1024*1024)
			if os.IsNotExist(e) && slicesEmptyReport(job.Tool) {
				raw = []byte("[]")
				e = nil
			}
			if e != nil {
				return errors.New("E_RESULT")
			}
		}
		if command.Format == "jwt" {
			record, e := jwtSummary(resource.Token)
			if e != nil {
				return e
			}
			if e = emit(record); e != nil {
				return e
			}
			continue
		}
		if e = emitEcosystemResults(job, raw, command.Format, ports, emit); e != nil {
			return e
		}
	}
	return nil
}
func slicesEmptyReport(tool string) bool { return tool == "sqlmap" || tool == "arjun" }
func recordConfidence(record map[string]any) string {
	if value, ok := record["confidence"].(string); ok {
		return value
	}
	return "observed"
}
func jwtSummary(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("E_RESOURCE")
	}
	decode := func(part string) (map[string]any, error) {
		data, e := base64.RawURLEncoding.Strict().DecodeString(part)
		if e != nil || len(data) > 16384 {
			return nil, errors.New("E_RESOURCE")
		}
		var doc map[string]any
		if json.Unmarshal(data, &doc) != nil {
			return nil, errors.New("E_RESOURCE")
		}
		return doc, nil
	}
	header, e := decode(parts[0])
	if e != nil {
		return nil, e
	}
	claims, e := decode(parts[1])
	if e != nil {
		return nil, e
	}
	names := []string{}
	for name := range claims {
		names = append(names, name)
	}
	sort.Strings(names)
	record := map[string]any{"kind": "jwt", "signatureVerified": false, "claimNames": names, "tokenSha256": hash([]byte(token)), "confidence": "unverified", "algorithm": jwtAlgorithm(header["alg"]), "sensitiveValues": "[REDACTED_SECRET]"}
	for _, key := range []string{"exp", "iat", "nbf"} {
		if value, ok := claims[key].(float64); ok {
			record[key] = value
		}
	}
	if header["alg"] == "none" {
		record["hypothesis"] = "unsigned-token"
	}
	return record, nil
}
func emitEcosystemResults(job JobRequest, raw []byte, format string, ports map[int]int, emit func(map[string]any) error) error {
	if format == "sqlmap" {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("[]")) {
			return nil
		}
		records, e := csv.NewReader(bytes.NewReader(raw)).ReadAll()
		if e != nil {
			return errors.New("E_RESULT")
		}
		if len(records) < 2 {
			return nil
		}
		column := -1
		for i, label := range records[0] {
			if strings.EqualFold(label, "Technique(s)") {
				column = i
			}
		}
		if column < 0 {
			return errors.New("E_RESULT")
		}
		for _, row := range records[1:] {
			if column < len(row) && strings.TrimSpace(row[column]) != "" {
				if e := emit(map[string]any{"kind": "analysis", "parameter": job.Parameters.Parameter, "hypothesis": "sql-injection-tool-signal", "confidence": "requires-review", "evidenceHash": hash(mustJSON(row))}); e != nil {
					return e
				}
			}
		}
		return nil
	}
	if format == "xml" {
		var report struct {
			Hosts []struct {
				Ports []struct {
					ID    int `xml:"portid,attr"`
					State struct {
						Value string `xml:"state,attr"`
					} `xml:"state"`
					Service struct {
						Name       string `xml:"name,attr"`
						Product    string `xml:"product,attr"`
						Version    string `xml:"version,attr"`
						Confidence string `xml:"conf,attr"`
					} `xml:"service"`
				} `xml:"ports>port"`
			} `xml:"host"`
		}
		if xml.Unmarshal(raw, &report) != nil {
			return errors.New("E_RESULT")
		}
		for _, host := range report.Hosts {
			for _, port := range host.Ports {
				if actual, ok := ports[port.ID]; ok && port.State.Value == "open" {
					record := map[string]any{"kind": "service", "port": actual, "target": sanitizeURL(job.Targets[0]), "transport": "tcp", "source": "approved-tunnel", "name": port.Service.Name, "product": port.Service.Product, "version": port.Service.Version, "fingerprintVerified": false}
					if e := emit(record); e != nil {
						return e
					}
				}
			}
		}
		return nil
	}
	var values []any
	if format == "json" {
		var doc any
		if json.Unmarshal(raw, &doc) != nil {
			return errors.New("E_RESULT")
		}
		switch value := doc.(type) {
		case []any:
			values = value
		case map[string]any:
			if job.Tool == "arjun" {
				for target, item := range value {
					m := object(item)
					values = append(values, map[string]any{"url": target, "params": m["params"]})
				}
			} else if list, ok := value["results"].([]any); ok {
				values = list
			} else if list, ok := value["findings"].([]any); ok {
				values = list
			} else if list, ok := value["vulnerabilities"].([]any); ok {
				values = list
			} else {
				values = []any{value}
			}
		}
	} else {
		scanner := bufio.NewScanner(bytes.NewReader(raw))
		scanner.Buffer(make([]byte, 8192), 128*1024)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			var value any
			if json.Unmarshal([]byte(line), &value) != nil {
				value = line
			}
			values = append(values, value)
			if len(values) > 10000 {
				return errors.New("E_SIZE")
			}
		}
		if scanner.Err() != nil {
			return errors.New("E_RESULT")
		}
	}
	for _, value := range values {
		if job.Tool == "nikto" {
			if list, ok := object(value)["vulnerabilities"].([]any); ok {
				for _, item := range list {
					record, e := normalizeEcosystemResult(job, item, ports)
					if e != nil {
						return e
					}
					if e = emit(record); e != nil {
						return e
					}
				}
				continue
			}
		}
		record, e := normalizeEcosystemResult(job, value, ports)
		if e != nil {
			return e
		}
		if e = emit(record); e != nil {
			return e
		}
	}
	return nil
}
func normalizeEcosystemResult(job JobRequest, value any, ports map[int]int) (map[string]any, error) {
	raw := object(value)
	plain, _ := value.(string)
	record := map[string]any{}
	text := func(keys ...string) string {
		for _, key := range keys {
			if v, ok := raw[key].(string); ok && v != "" {
				return v
			}
		}
		return ""
	}
	switch job.Tool {
	case "subfinder", "amass", "alterx":
		name := text("host", "name", "domain")
		if name == "" {
			name = plain
		}
		name = strings.TrimSpace(name)
		if strings.HasPrefix(name, "[") {
			return nil, nil
		}
		normalized, e := normalizeHost(name)
		belongs := false
		for _, target := range job.Targets {
			if u, err := url.Parse(target); err == nil && (normalized == u.Hostname() || strings.HasSuffix(normalized, "."+u.Hostname())) {
				belongs = true
			}
		}
		if e != nil || !belongs {
			return nil, nil
		}
		record = map[string]any{"kind": "asset", "name": normalized, "source": text("source"), "activeVerified": false, "candidate": true}
	case "uncover":
		record = map[string]any{"kind": "asset", "host": text("ip", "host"), "port": raw["port"], "source": "shodan-idb", "activeVerified": false, "candidate": true}
		if record["host"] == "" {
			return nil, nil
		}
	case "dnsx":
		name := text("host")
		if name == "" {
			return nil, nil
		}
		record = map[string]any{"kind": "dns", "name": name, "ttlKnown": false, "dnssecVerified": false}
		for _, key := range []string{"a", "aaaa", "cname", "mx", "ns", "txt", "status_code"} {
			if v := raw[key]; v != nil {
				record[key] = v
			}
		}
	case "gau", "waybackurls":
		address := text("url")
		if address == "" {
			address = plain
		}
		u, e := url.Parse(address)
		if e != nil || u.Host == "" || u.Scheme != "http" && u.Scheme != "https" {
			return nil, nil
		}
		record = map[string]any{"kind": "endpoint", "url": sanitizeURL(address), "method": "GET", "historical": true, "fetched": false, "source": "wayback", "blocked": !allows(job.Scope, address)}
	case "naabu":
		port := int(number(raw["port"]))
		actual, ok := ports[port]
		if !ok {
			return nil, nil
		}
		record = map[string]any{"kind": "service", "target": sanitizeURL(job.Targets[0]), "port": actual, "transport": "tcp", "source": "approved-tunnel", "fingerprintVerified": false}
	case "ffuf":
		address := text("url")
		if address == "" {
			return nil, nil
		}
		record = map[string]any{"kind": "endpoint", "url": sanitizeURL(address), "method": "GET", "status": raw["status"], "length": raw["length"], "fetched": true, "confidence": "observed"}
		if job.Capability == "web.vhosts.fuzz" {
			record["virtualHost"] = object(raw["input"])["FUZZ"]
		}
		if job.Capability == "http.parameters.fuzz" {
			record["kind"] = "analysis"
			record["parameter"] = job.Parameters.Parameter
		}
	case "arjun":
		record = map[string]any{"kind": "analysis", "url": sanitizeURL(text("url")), "parameters": raw["params"], "hypothesis": "parameter-candidates", "confidence": "requires-review"}
	case "dalfox":
		if !slices.Contains([]string{"V", "R", "A", "I"}, text("type")) || text("param") != job.Parameters.Parameter {
			return nil, nil
		}
		record = map[string]any{"kind": "analysis", "url": sanitizeURL(job.Targets[0]), "parameter": job.Parameters.Parameter, "hypothesis": "xss-tool-signal", "confidence": "requires-review", "type": text("type", "poc_type"), "evidenceHash": hash(mustJSON(value))}
	case "testssl":
		id := text("id")
		if id == "" {
			return nil, nil
		}
		record = map[string]any{"kind": "tls", "target": sanitizeURL(job.Targets[0]), "check": id, "severity": text("severity"), "summary": text("finding"), "originalServerTLS": true}
	case "nikto":
		record = map[string]any{"kind": "analysis", "url": sanitizeURL(job.Targets[0]), "rule": text("id", "OSVDB"), "summary": text("msg", "message"), "confidence": "requires-review", "evidenceHash": hash(mustJSON(value))}
		if record["summary"] == "" {
			return nil, nil
		}
	case "gitleaks":
		record = map[string]any{"kind": "secret", "rule": text("RuleID"), "path": snapshotDisplayPath(text("File")), "line": raw["StartLine"], "secret": "[REDACTED_SECRET]", "onlineVerified": false, "evidenceHash": hash(mustJSON(value))}
	case "trufflehog":
		metadata := object(object(object(raw["SourceMetadata"])["Data"])["Filesystem"])
		record = map[string]any{"kind": "secret", "rule": text("DetectorName"), "path": snapshotDisplayPath(fmt.Sprint(metadata["file"])), "line": metadata["line"], "secret": "[REDACTED_SECRET]", "onlineVerified": false, "evidenceHash": hash(mustJSON(value))}
	case "semgrep":
		record = map[string]any{"kind": "analysis", "rule": text("check_id"), "path": snapshotDisplayPath(text("path")), "line": object(raw["start"])["line"], "summary": object(raw["extra"])["message"], "severity": object(raw["extra"])["severity"], "confidence": "requires-review", "evidenceHash": hash(mustJSON(value))}
	default:
		return nil, errors.New("E_RESULT")
	}
	if u, _ := url.Parse(job.Targets[0]); u != nil {
		if name, ok := record["name"].(string); ok {
			copy := *u
			copy.Host = name
			record["blocked"] = !allows(job.Scope, copy.String())
		}
	}
	return record, nil
}
func snapshotDisplayPath(value string) string {
	value = filepath.ToSlash(value)
	value = strings.TrimPrefix(value, "/tmp/snapshot/")
	if value == "" || strings.HasPrefix(value, "/") || strings.Contains(value, ":") || strings.Contains(value, "..") {
		return "[REDACTED_PATH]"
	}
	return value
}
func mustJSON(value any) []byte { data, _ := json.Marshal(value); return data }
func number(value any) float64  { v, _ := value.(float64); return v }

var ecosystemToken = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,63}$`)

func ecosystemEnvironment(proxy, rootPath string) []string {
	return []string{"PATH=/opt/venv/bin:/usr/local/bin:/usr/bin:/bin", "HOME=/tmp", "XDG_CONFIG_HOME=/tmp/config", "USER=65532", "NO_COLOR=1", "SSL_CERT_FILE=" + rootPath, "REQUESTS_CA_BUNDLE=" + rootPath, "CURL_CA_BUNDLE=" + rootPath, "HTTP_PROXY=" + proxy, "HTTPS_PROXY=" + proxy, "http_proxy=" + proxy, "https_proxy=" + proxy, "NO_PROXY=", "PYTHONDONTWRITEBYTECODE=1", "PYTHONPATH=/opt/tools/arjun", "SEMGREP_SEND_METRICS=off"}
}

func jwtAlgorithm(value any) string {
	v, _ := value.(string)
	if slices.Contains([]string{"none", "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "EdDSA"}, v) {
		return v
	}
	return "unknown"
}
