package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sort"
	"strings"
)

func object(value any) map[string]any { v, _ := value.(map[string]any); return v }
func redactedString(value string, job JobRequest) string {
	for _, h := range job.Headers {
		if h.Value == "" {
			continue
		}
		value = strings.ReplaceAll(value, h.Value, "[REDACTED_SECRET]")
		if strings.EqualFold(h.Name, "authorization") {
			for _, part := range strings.Fields(h.Value)[min(1, len(strings.Fields(h.Value))):] {
				value = strings.ReplaceAll(value, part, "[REDACTED_SECRET]")
			}
		}
		if strings.EqualFold(h.Name, "cookie") {
			for _, part := range strings.Split(h.Value, ";") {
				if _, token, ok := strings.Cut(part, "="); ok && strings.TrimSpace(token) != "" {
					value = strings.ReplaceAll(value, strings.TrimSpace(token), "[REDACTED_SECRET]")
				}
			}
		}
	}
	return value
}
func schemaEvents(reader io.Reader, job JobRequest, schemaHash string) ([]json.RawMessage, error) {
	scanner := bufio.NewScanner(io.LimitReader(reader, 16*1024*1024+1))
	scanner.Buffer(make([]byte, 8192), 8*1024*1024)
	cases := map[string]bool{}
	failures := map[string]map[string]any{}
	statuses := map[string]int{}
	tested, blocked, total := 0, 0, 0
	completed := false
	for scanner.Scan() {
		total += len(scanner.Bytes())
		if total > 16*1024*1024 {
			return nil, errors.New("E_SIZE")
		}
		var event map[string]any
		if json.Unmarshal(scanner.Bytes(), &event) != nil {
			return nil, errors.New("E_RESULT")
		}
		if event["FatalError"] != nil {
			return nil, errors.New("E_EXECUTOR")
		}
		if event["EngineFinished"] != nil {
			completed = true
		}
		scenario := object(event["ScenarioFinished"])
		if scenario == nil {
			continue
		}
		recorder := object(scenario["recorder"])
		interactions := object(recorder["interactions"])
		checks := object(recorder["checks"])
		for id, value := range interactions {
			if cases[id] {
				continue
			}
			cases[id] = true
			interaction := object(value)
			response := object(interaction["response"])
			header := object(response["headers"])
			denied := false
			for name := range header {
				if strings.EqualFold(name, "x-catbridge-blocked") {
					denied = true
				}
			}
			if denied {
				blocked++
				continue
			}
			if response == nil {
				statuses["unavailable"]++
				continue
			}
			tested++
			status, _ := response["status_code"].(float64)
			encoded, _ := json.Marshal(int(status))
			statuses[string(encoded)]++
			nodes, _ := checks[id].([]any)
			for _, node := range nodes {
				check := object(node)
				info := object(check["failure_info"])
				if info == nil {
					continue
				}
				name, _ := check["name"].(string)
				if name == "" {
					continue
				}
				request := object(interaction["request"])
				method, _ := request["method"].(string)
				uri, _ := request["uri"].(string)
				key := name
				failure := object(info["failure"])
				result := map[string]any{"check": name, "type": failure["type"], "status": int(status), "caseId": id, "request": map[string]any{"method": method, "url": sanitizeURL(redactedString(uri, job)), "bodyExcluded": true, "credentialsExcluded": true}, "minimized": scenario["is_final"] == true}
				previous := failures[key]
				if previous == nil || scenario["is_final"] == true {
					failures[key] = result
				}
			}
		}
	}
	if scanner.Err() != nil {
		return nil, errors.New("E_SIZE")
	}
	if !completed {
		return nil, errors.New("E_EXECUTOR")
	}
	names := []string{}
	for name := range failures {
		names = append(names, name)
	}
	sort.Strings(names)
	results := []any{}
	for _, name := range names {
		results = append(results, failures[name])
	}
	status := "passed"
	if len(results) > 0 {
		status = "contract-failure"
	}
	if tested == 0 || blocked > 0 {
		status = "incomplete"
	}
	data, e := json.Marshal(map[string]any{"kind": "api_test", "url": sanitizeURL(job.Targets[0]), "operations": job.Parameters.Operations, "seed": job.Parameters.Seed, "schemaHash": schemaHash, "confidence": "observed", "status": status, "tested": tested, "blocked": blocked, "statuses": statuses, "failures": results})
	if e != nil || len(data) > 128*1024 {
		return nil, errors.New("E_SIZE")
	}
	return []json.RawMessage{data}, nil
}
func emitSchemaEvents(job JobRequest, schema []byte) error {
	file, e := os.Open("/tmp/events.ndjson")
	if e != nil {
		return errors.New("E_RESULT")
	}
	defer file.Close()
	results, e := schemaEvents(file, job, hash(schema))
	if e != nil {
		return e
	}
	for _, result := range results {
		if _, e = os.Stdout.Write(append(bytes.Clone(result), '\n')); e != nil {
			return e
		}
	}
	return nil
}
