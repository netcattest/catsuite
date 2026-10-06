package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

type RunnerInput struct {
	Policy BrokerPolicy `json:"policy"`
	Root   string       `json:"root"`
	Schema string       `json:"schema,omitempty"`
}

func (b *Bridge) dockerCommand(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, b.docker, args...)
	cmd.Env = append(minimalEnvironment(), "DOCKER_CONFIG="+filepath.Join(b.directory, "docker-config"))
	if b.dockerHost != "" {
		cmd.Env = append(cmd.Env, "DOCKER_HOST="+b.dockerHost)
	}
	return cmd
}
func (b *Bridge) dockerOutput(ctx context.Context, args ...string) ([]byte, error) {
	cmd := b.dockerCommand(ctx, args...)
	cmd.Stderr = io.Discard
	return cmd.Output()
}
func (b *Bridge) executeTool(ctx context.Context, input JobRequest, owner string, emit func(json.RawMessage) error) error {
	image := b.tools[input.Tool]
	suffix := input.ID[:16] + "-" + randomCode()[:8]
	suffix = strings.ToLower(strings.NewReplacer("_", "a", "-", "b").Replace(suffix))
	volume := "catbridge-ipc-" + suffix
	brokerName := "catbridge-broker-" + suffix
	runnerName := "catbridge-tool-" + suffix
	cleanup := func() {
		end, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		b.dockerOutput(end, "rm", "-f", runnerName, brokerName)
		b.dockerOutput(end, "volume", "rm", volume)
	}
	defer cleanup()
	if _, e := b.dockerOutput(ctx, "volume", "create", volume); e != nil {
		return errors.New("E_RUNTIME_UNAVAILABLE")
	}
	policy := BrokerPolicy{Job: input, HostScope: b.scope}
	policy.ProviderFixtures = b.providerFixtures
	policy.DNSFixtures = b.dnsFixtures
	if b.upstreamCA != "" {
		data, e := limitedFile(b.upstreamCA, 128*1024)
		if e != nil {
			return errors.New("E_TLS")
		}
		policy.CA = string(data)
	}
	config, _ := json.Marshal(policy)
	brokerArgs := []string{"run", "--name", brokerName, "--rm", "-i", "--network", b.runtimeNetwork, "--user", "65532:65532", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--memory=128m", "--cpus=0.5", "--pids-limit=32", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m", "--mount", "type=volume,source=" + volume + ",target=/ipc", b.brokerImage.Image, "broker"}
	cmd := b.dockerCommand(ctx, brokerArgs...)
	cmd.Stdin = bytes.NewReader(config)
	cmd.Stderr = io.Discard
	pipe, e := cmd.StdoutPipe()
	if e != nil {
		return e
	}
	if e = cmd.Start(); e != nil {
		return errors.New("E_RUNTIME_UNAVAILABLE")
	}
	reader := bufio.NewReader(io.LimitReader(pipe, 1024*1024))
	readyCh := make(chan []byte, 1)
	go func() { line, _ := reader.ReadBytes('\n'); readyCh <- line }()
	var ready struct {
		Root string `json:"root"`
	}
	select {
	case line := <-readyCh:
		if json.Unmarshal(line, &ready) != nil || !strings.Contains(ready.Root, "BEGIN CERTIFICATE") {
			cmd.Process.Kill()
			cmd.Wait()
			return errors.New("E_RUNTIME_UNAVAILABLE")
		}
	case <-ctx.Done():
		cmd.Process.Kill()
		cmd.Wait()
		return ctx.Err()
	case <-time.After(20 * time.Second):
		cmd.Process.Kill()
		cmd.Wait()
		return errors.New("E_RUNTIME_UNAVAILABLE")
	}
	runner := RunnerInput{Policy: policy, Root: ready.Root}
	if input.Resource != "" {
		data, e := b.resourceFor(input, owner)
		if e != nil {
			return e
		}
		runner.Schema = base64.StdEncoding.EncodeToString(data)
	}
	payload, _ := json.Marshal(runner)
	args := []string{"run", "--name", runnerName, "--rm", "-i", "--network=none", "--dns", "127.0.0.1", "--user", "65532:65532", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--memory=512m", "--cpus=1", "--pids-limit=64", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m", "--mount", "type=volume,source=" + volume + ",target=/ipc,readonly", image.Image, "runner"}
	task := b.dockerCommand(ctx, args...)
	task.Stdin = bytes.NewReader(payload)
	task.Stderr = io.Discard
	out, e := task.StdoutPipe()
	if e != nil {
		return e
	}
	if e = task.Start(); e != nil {
		return errors.New("E_RUNTIME_UNAVAILABLE")
	}
	scanner := bufio.NewScanner(io.LimitReader(out, 16*1024*1024+1))
	scanner.Buffer(make([]byte, 8192), 128*1024)
	total := 0
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		total += len(line)
		if total > 16*1024*1024 {
			e = errors.New("E_SIZE")
			break
		}
		if len(line) == 0 {
			continue
		}
		if e = emit(append(json.RawMessage{}, line...)); e != nil {
			break
		}
	}
	if e == nil {
		e = scanner.Err()
	}
	if e != nil {
		task.Process.Kill()
	}
	wait := task.Wait()
	if e == nil && wait != nil {
		e = errors.New("E_EXECUTOR")
	}
	end, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	b.dockerOutput(end, "stop", "--time", "3", brokerName)
	rest, _ := io.ReadAll(reader)
	cmd.Wait()
	for _, line := range bytes.Split(rest, []byte{'\n'}) {
		if len(line) > 0 && json.Valid(line) {
			if x := emit(line); e == nil && x != nil {
				e = x
			}
		}
	}
	return e
}
func runtimeEntry(mode string) error {
	if mode == "broker" {
		var policy BrokerPolicy
		if json.NewDecoder(io.LimitReader(os.Stdin, 256*1024+1)).Decode(&policy) != nil {
			return errors.New("E_JOB")
		}
		broker, e := newHTTPBroker(policy)
		if e != nil {
			return e
		}
		socket, e := net.Listen("unix", "/ipc/broker.sock")
		if e != nil {
			return e
		}
		defer os.Remove("/ipc/broker.sock")
		os.Chmod("/ipc/broker.sock", 0600)
		server := &http.Server{Handler: broker, ReadHeaderTimeout: 5 * time.Second, MaxHeaderBytes: 16 * 1024}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		go func() { <-ctx.Done(); server.Close(); broker.transport.CloseIdleConnections() }()
		json.NewEncoder(os.Stdout).Encode(map[string]string{"root": string(broker.pem)})
		e = server.Serve(socket)
		for _, discovery := range broker.discovered() {
			fmt.Println(string(discovery))
		}
		fmt.Println(string(broker.summary()))
		if errors.Is(e, http.ErrServerClosed) {
			return nil
		}
		return e
	}
	var input RunnerInput
	if json.NewDecoder(io.LimitReader(os.Stdin, 4*1024*1024+1)).Decode(&input) != nil {
		return errors.New("E_JOB")
	}
	if _, e := newHTTPBroker(input.Policy); e != nil {
		return e
	}
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return e
	}
	defer listener.Close()
	go func() {
		for {
			local, e := listener.Accept()
			if e != nil {
				return
			}
			go func() {
				defer local.Close()
				remote, e := net.DialTimeout("unix", "/ipc/broker.sock", 5*time.Second)
				if e != nil {
					return
				}
				defer remote.Close()
				done := make(chan struct{})
				go func() {
					io.Copy(remote, local)
					if c, ok := remote.(*net.UnixConn); ok {
						c.CloseWrite()
					}
					close(done)
				}()
				io.Copy(local, remote)
				local.Close()
				<-done
			}()
		}
	}()
	proxy := "http://" + listener.Addr().String()
	rootPath := "/tmp/task-ca.pem"
	if os.WriteFile(rootPath, []byte(input.Root), 0600) != nil {
		return errors.New("E_STORAGE")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(input.Policy.Job.Timeout)*time.Second)
	defer cancel()
	job := input.Policy.Job
	p := job.Parameters
	if _, ok := ecosystemVersions[job.Tool]; ok {
		return runEcosystem(ctx, input, proxy, rootPath)
	}
	var binary string
	args := []string{}
	switch job.Tool {
	case "httpx":
		binary = "/opt/tools/httpx"
		args = []string{"-silent", "-json", "-no-color", "-disable-update-check", "-no-fallback-scheme", "-status-code", "-content-length", "-content-type", "-title", "-tech-detect", "-location", "-include-response-header", "-threads", "2", "-rate-limit", fmt.Sprint(job.Rate), "-timeout", "10", "-retries", "0", "-proxy", proxy, "-x", strings.Join(p.Methods, ",")}
		for _, target := range job.Targets {
			args = append(args, "-u", target)
		}
	case "katana":
		binary = "/opt/tools/katana"
		args = []string{"-silent", "-jsonl", "-no-color", "-disable-update-check", "-js-crawl", "-form-extraction", "-omit-raw", "-omit-body", "-depth", fmt.Sprint(p.Depth), "-concurrency", "2", "-parallelism", "1", "-rate-limit", fmt.Sprint(job.Rate), "-timeout", "10", "-retry", "0", "-max-response-size", "2097152", "-disable-redirects", "-proxy", proxy}
		for _, target := range job.Targets {
			args = append(args, "-u", target)
		}
	case "schemathesis":
		binary = "/opt/venv/bin/st"
		data, e := base64.StdEncoding.Strict().DecodeString(input.Schema)
		if e != nil || len(data) > 2*1024*1024 {
			return errors.New("E_SCHEMA")
		}
		doc, e := schemaDocument(data)
		if e != nil {
			return e
		}
		filtered := map[string]any{}
		paths := doc["paths"].(map[string]any)
		for _, operation := range p.Operations {
			parts := strings.SplitN(operation, " ", 2)
			if len(parts) != 2 {
				return errors.New("E_SCHEMA_OPERATION")
			}
			original, _ := paths[parts[1]].(map[string]any)
			item, _ := filtered[parts[1]].(map[string]any)
			if item == nil {
				item = map[string]any{}
				filtered[parts[1]] = item
			}
			if parameters := original["parameters"]; parameters != nil {
				item["parameters"] = parameters
			}
			value, _ := original[strings.ToLower(parts[0])].(map[string]any)
			if value == nil {
				return errors.New("E_SCHEMA_OPERATION")
			}
			delete(value, "servers")
			delete(value, "callbacks")
			item[strings.ToLower(parts[0])] = value
		}
		doc["paths"] = filtered
		delete(doc, "servers")
		delete(doc, "webhooks")
		wire, _ := json.Marshal(doc)
		if os.WriteFile("/tmp/schema.json", wire, 0600) != nil {
			return errors.New("E_STORAGE")
		}
		args = []string{"run", "/tmp/schema.json", "--url", job.Targets[0], "--workers", "1", "--phases", "examples,fuzzing", "--checks", "not_a_server_error,status_code_conformance,content_type_conformance,response_headers_conformance,response_schema_conformance", "--max-examples", fmt.Sprint(p.Examples), "--seed", fmt.Sprint(p.Seed), "--generation-with-security-parameters", "false", "--request-retries", "0", "--request-timeout", "10", "--max-redirects", "0", "--rate-limit", fmt.Sprintf("%d/s", job.Rate), "--proxy", proxy, "--tls-verify", rootPath, "--generation-database", "/tmp/hypothesis", "--report-ndjson-path", "/tmp/events.ndjson", "--report-json-path", "/tmp/results.json", "--output-sanitize", "true", "--no-color"}
	default:
		return errPermission
	}
	digest, e := fileHash(binary)
	if e != nil || digest != job.ExpectedBinary {
		return errors.New("E_TOOL_CHANGED")
	}
	task := exec.CommandContext(ctx, binary, args...)
	task.Env = []string{"PATH=/opt/venv/bin:/usr/bin:/bin", "HOME=/tmp", "XDG_CONFIG_HOME=/tmp/config", "NO_COLOR=1", "SSL_CERT_FILE=" + rootPath, "REQUESTS_CA_BUNDLE=" + rootPath, "HYPOTHESIS_STORAGE_DIRECTORY=/tmp/hypothesis", "PYTHONDONTWRITEBYTECODE=1", "SCHEMATHESIS_TELEMETRY=false"}
	task.Stderr = io.Discard
	if job.Tool == "schemathesis" {
		task.Stdout = io.Discard
		e = task.Run()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if exit, ok := e.(*exec.ExitError); e != nil && (!ok || exit.ExitCode() != 1) {
			return errors.New("E_EXECUTOR")
		}
		schema, _ := base64.StdEncoding.Strict().DecodeString(input.Schema)
		return emitSchemaEvents(job, schema)
	}
	out, e := task.StdoutPipe()
	if e != nil {
		return e
	}
	if e = task.Start(); e != nil {
		return e
	}
	scanner := bufio.NewScanner(io.LimitReader(out, 16*1024*1024+1))
	scanner.Buffer(make([]byte, 8192), 128*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		normalized, e := normalizeToolResult(job, line)
		if e != nil {
			task.Process.Kill()
			task.Wait()
			return e
		}
		if normalized != nil {
			fmt.Println(string(normalized))
		}
	}
	if e = scanner.Err(); e != nil {
		task.Process.Kill()
		task.Wait()
		return errors.New("E_RESULT")
	}
	if task.Wait() != nil {
		return errors.New("E_EXECUTOR")
	}
	return nil
}
func sanitizeURL(value string) string {
	u, e := url.Parse(value)
	if e != nil {
		return "[INVALID_URL]"
	}
	u.User = nil
	u.Fragment = ""
	q := u.Query()
	for name := range q {
		lower := strings.ToLower(name)
		if strings.Contains(lower, "token") || strings.Contains(lower, "secret") || strings.Contains(lower, "password") || strings.Contains(lower, "key") || strings.Contains(lower, "credential") || strings.Contains(lower, "authorization") || strings.Contains(lower, "session") || strings.Contains(lower, "signature") || lower == "code" || lower == "passwd" {
			q.Set(name, "[REDACTED_SECRET]")
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}
func normalizeToolResult(job JobRequest, line []byte) (json.RawMessage, error) {
	var raw map[string]any
	if json.Unmarshal(line, &raw) != nil {
		return nil, errors.New("E_RESULT")
	}
	result := map[string]any{"confidence": "observed"}
	if job.Tool == "httpx" {
		if headers, ok := raw["header"].(map[string]any); ok && brokerBlocked(headers) {
			return nil, nil
		}
		value, _ := raw["url"].(string)
		if value == "" {
			return nil, errors.New("E_RESULT")
		}
		result["kind"] = "http_service"
		result["url"] = sanitizeURL(value)
		for _, field := range []string{"status_code", "content_length", "content_type", "title", "tech", "location"} {
			if value := raw[field]; value != nil {
				result[field] = value
			}
		}
		if headers, ok := raw["header"].(map[string]any); ok {
			selected := map[string]any{}
			for _, name := range []string{"server", "content_type", "cache_control", "x_content_type_options", "strict_transport_security"} {
				if value := headers[name]; value != nil {
					selected[name] = value
				}
			}
			result["headers"] = selected
		}
	} else {
		request, _ := raw["request"].(map[string]any)
		value, _ := request["endpoint"].(string)
		if value == "" {
			return nil, nil
		}
		result["kind"] = "endpoint"
		result["url"] = sanitizeURL(value)
		result["method"] = request["method"]
		for _, field := range []string{"source", "tag", "attribute"} {
			if value := request[field]; value != nil {
				result[field] = value
			}
		}
		response, _ := raw["response"].(map[string]any)
		headers, _ := response["headers"].(map[string]any)
		result["fetched"] = response["status_code"] != nil && !brokerBlocked(headers)
		if brokerBlocked(headers) {
			result["blocked"] = true
		}
		if response["status_code"] != nil {
			result["status"] = response["status_code"]
		}
		if forms, ok := response["forms"].([]any); ok {
			selected := []any{}
			for _, item := range forms[:min(len(forms), 25)] {
				form := object(item)
				clean := map[string]any{}
				for _, key := range []string{"method", "action", "enctype", "parameters"} {
					if value := form[key]; value != nil {
						clean[key] = value
					}
				}
				selected = append(selected, clean)
			}
			result["forms"] = selected
		}
		if endpoint, e := url.Parse(value); e == nil {
			names := []string{}
			for name := range endpoint.Query() {
				names = append(names, name)
			}
			sort.Strings(names)
			result["parameters"] = names
		}
	}
	data, _ := json.Marshal(cleanToolValue(result, job, 0))
	if len(data) > 128*1024 {
		return nil, errors.New("E_SIZE")
	}
	return data, nil
}
func brokerBlocked(headers map[string]any) bool {
	for name, value := range headers {
		if strings.EqualFold(strings.ReplaceAll(name, "_", "-"), "x-catbridge-blocked") && strings.EqualFold(fmt.Sprint(value), "true") {
			return true
		}
	}
	return false
}
func cleanToolValue(value any, job JobRequest, depth int) any {
	if depth > 16 {
		return nil
	}
	switch v := value.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, item := range v {
			out[redactedString(k, job)] = cleanToolValue(item, job, depth+1)
		}
		return out
	case []any:
		out := []any{}
		for _, item := range v[:min(len(v), 100)] {
			out = append(out, cleanToolValue(item, job, depth+1))
		}
		return out
	case string:
		v = redactedString(v, job)
		if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
			v = sanitizeURL(v)
		}
		if len(v) > 2048 {
			v = v[:2048]
		}
		return v
	default:
		return v
	}
}
