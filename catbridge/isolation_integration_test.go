package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLinuxContainerIsolation(t *testing.T) {
	lockPath := os.Getenv("CATBRIDGE_LINUX_LAB")
	if lockPath == "" {
		t.Skip("Linux container integration requires CATBRIDGE_LINUX_LAB")
	}
	b, _, _ := setupBridge(t)
	fingerprint, e := os.ReadFile(filepath.Join(filepath.Dir(lockPath), "author.sha256"))
	if e != nil {
		t.Fatal(e)
	}
	if e = b.loadToolLock(lockPath, strings.TrimSpace(string(fingerprint))); e != nil || b.runtimeError != "" {
		t.Fatal(e, b.runtimeError)
	}
	data, _ := os.ReadFile(lockPath)
	var doc map[string]any
	json.Unmarshal(data, &doc)
	base := doc["preparation"].(map[string]any)["base"].(string)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	probe := `import os,socket
assert os.getuid()==65532
assert not os.path.exists('/var/run/docker.sock')
status=open('/proc/self/status').read()
assert 'CapEff:\t0000000000000000' in status
assert 'NoNewPrivs:\t1' in status
try:
 open('/root-write-test','w').write('forbidden')
 raise AssertionError('root writable')
except OSError:
 pass
try:
 socket.create_connection(('1.1.1.1',443),timeout=1)
 raise AssertionError('network bypass')
except OSError:
 pass
print('isolated')`
	out, e := b.dockerOutput(ctx, "run", "--rm", "--network=none", "--user", "65532:65532", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--memory=64m", "--cpus=0.5", "--pids-limit=16", "--tmpfs", "/tmp:rw,noexec,nosuid,size=4m", base, "python", "-c", probe)
	if e != nil || strings.TrimSpace(string(out)) != "isolated" {
		t.Fatal("Isolation failed", string(out), e)
	}
	name := "catsuite-memory-" + strings.ToLower(strings.NewReplacer("_", "a", "-", "b").Replace(randomCode()[:8]))
	defer b.dockerOutput(context.Background(), "rm", "-f", name)
	if _, e = b.dockerOutput(ctx, "run", "--name", name, "--network=none", "--user", "65532:65532", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--memory=32m", "--memory-swap=32m", "--pids-limit=16", base, "python", "-c", "allocation=bytearray(256*1024*1024)"); e == nil {
		t.Fatal("Memory quota bypass")
	}
	out, e = b.dockerOutput(ctx, "inspect", "--format", "{{.State.OOMKilled}}", name)
	if e != nil || strings.TrimSpace(string(out)) != "true" {
		t.Fatal("Missing OOM evidence", string(out), e)
	}
}
