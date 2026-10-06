package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSignedProfileRejectsTamperingExpiryAndDowngrade(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Unix(1700000000, 0)
	body := []byte(`{"capability":"nuclei.scan"}`)
	request, _ := http.NewRequest("POST", "https://bridge.test:8743/v2/jobs", bytes.NewReader(body))
	if e := signMessage(request.Header, request, 0, body, testID, key, now); e != nil {
		t.Fatal(e)
	}
	if _, _, e := verifyMessage(request.Header, request, 0, body, testID, &key.PublicKey, now); e != nil {
		t.Fatal(e)
	}
	mutations := []func(*http.Request, []byte){func(r *http.Request, b []byte) { r.Method = "DELETE" }, func(r *http.Request, b []byte) { r.URL.Path = "/v2/revoke" }, func(r *http.Request, b []byte) { r.Host = "other.test" }, func(r *http.Request, b []byte) { r.Header.Set("X-Cat-Protocol", "1") }, func(r *http.Request, b []byte) { r.Header.Add("X-Cat-Message", randomCode()) }, func(r *http.Request, b []byte) { b[1] = 'x' }, func(r *http.Request, b []byte) { r.Header.Set("X-Cat-Device", "foreign") }}
	for index, mutate := range mutations {
		copy := request.Clone(request.Context())
		copy.Header = request.Header.Clone()
		b := append([]byte{}, body...)
		mutate(copy, b)
		if _, _, e := verifyMessage(copy.Header, copy, 0, b, testID, &key.PublicKey, now); e == nil {
			t.Fatal(index)
		}
	}
	if _, _, e := verifyMessage(request.Header, request, 0, body, testID, &key.PublicKey, now.Add(60*time.Second)); e == nil {
		t.Fatal("Expired message")
	}
	response := make(http.Header)
	signMessage(response, request, 200, body, testID, key, now)
	if _, _, e := verifyMessage(response, request, 200, body, testID, &key.PublicKey, now); e != nil {
		t.Fatal(e)
	}
	if _, _, e := verifyMessage(response, request, 202, body, testID, &key.PublicKey, now); e == nil {
		t.Fatal("Status changed")
	}
	other := request.Clone(request.Context())
	other.Header = request.Header.Clone()
	other.Header.Set("X-Cat-Message", randomCode())
	if _, _, e := verifyMessage(response, other, 200, body, testID, &key.PublicKey, now); e == nil {
		t.Fatal("Response borrowed")
	}
}
func TestReplayJournalSurvivesRestartAndBlocksBeforeEffects(t *testing.T) {
	b, s, c := setupBridge(t)
	paired := pairedClient(t, b, s, c)
	body := []byte(`{}`)
	request, _ := http.NewRequest("POST", s.URL+"/v2/jobs", bytes.NewReader(body))
	signMessage(request.Header, request, 0, body, testID, testKeys[paired], time.Now())
	response, e := paired.Do(request)
	if e != nil {
		t.Fatal(e)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	copy := request.Clone(request.Context())
	copy.Body = io.NopCloser(bytes.NewReader(body))
	response, e = paired.Do(copy)
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	wire, _ := io.ReadAll(response.Body)
	if response.StatusCode != 403 || !bytes.Contains(wire, []byte("E_REPLAY")) || len(b.jobs) != 0 {
		t.Fatal(string(wire))
	}
	nonce, expires, e := verifyMessage(request.Header, request, 0, body, testID, &testKeys[paired].PublicKey, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	restarted := &Bridge{directory: b.directory}
	if e = restarted.acceptMessage(testID, nonce, request.Header.Get("X-Cat-Message"), expires); e == nil {
		t.Fatal("Replay after restart")
	}
	status, result := requestTest(t, paired, "GET", s.URL+"/v1/capabilities", nil)
	if status != 426 || result["error"] != "E_PROTOCOL" {
		t.Fatal(result)
	}
}
func TestGrantCannotBeBorrowedOrModified(t *testing.T) {
	b, s, c := setupBridge(t)
	paired := pairedClient(t, b, s, c)
	input := validJob(b)
	status, grant := requestTest(t, paired, "POST", s.URL+"/v2/authorizations", input)
	if status != 200 {
		t.Fatal(grant)
	}
	input.Authorization = grant["authorization"].(string)
	if e := b.verifyAuthorization(input, testID); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*JobRequest){func(j *JobRequest) { j.Flow = "22345678-1234-4234-8234-123456789012" }, func(j *JobRequest) { j.Revision = strings.Repeat("e", 64) }, func(j *JobRequest) { j.Node = "other" }, func(j *JobRequest) { j.Capability = "shell.run" }, func(j *JobRequest) { j.Rate = 4 }, func(j *JobRequest) { j.Targets = []string{"https://other.test"} }} {
		copy := input
		mutate(&copy)
		if e := b.verifyAuthorization(copy, testID); e == nil {
			t.Fatal("Borrowed grant")
		}
	}
	if e := b.verifyAuthorization(input, "different"); e == nil {
		t.Fatal("Foreign device")
	}
	last := "A"
	if strings.HasSuffix(input.Authorization, "A") {
		last = "B"
	}
	input.Authorization = input.Authorization[:len(input.Authorization)-1] + last
	if e := b.verifyAuthorization(input, testID); e == nil {
		t.Fatal("Tampered grant")
	}
}
func TestCrossLanguageSignatureFixture(t *testing.T) {
	path := filepath.Join("testdata", "catbridge-v2.json")
	if os.Getenv("CAT_GENERATE_VECTOR") == "1" {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
		now := time.Unix(1700000000, 0)
		request, _ := http.NewRequest("POST", "https://bridge.test:8743/v2/jobs", nil)
		body := []byte(`{"capability":"nuclei.scan","revision":"fixture"}`)
		signMessage(request.Header, request, 0, body, testID, key, now)
		result := []byte(`{"id":"fixture","status":"complete","results":[]}`)
		response := make(http.Header)
		signMessage(response, request, 200, result, testID, key, now)
		os.MkdirAll(filepath.Dir(path), 0700)
		if e := writeJSON(path, map[string]any{"publicKey": base64.StdEncoding.EncodeToString(pub), "identity": testID, "now": now.Unix(), "method": request.Method, "target": request.URL.String(), "body": base64.StdEncoding.EncodeToString(body), "request": request.Header, "response": response, "responseBody": base64.StdEncoding.EncodeToString(result), "requestMessage": request.Header.Get("X-Cat-Message")}); e != nil {
			t.Fatal(e)
		}
	}
	var fixture struct {
		PublicKey, Identity, Method, Target, Body, ResponseBody, RequestMessage string
		Now                                                                     int64
		Request, Response                                                       http.Header
	}
	bytes, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if json.Unmarshal(bytes, &fixture) != nil {
		t.Fatal("Fixture")
	}
	public, _ := base64.StdEncoding.DecodeString(fixture.PublicKey)
	parsed, e := x509.ParsePKIXPublicKey(public)
	if e != nil {
		t.Fatal(e)
	}
	key := parsed.(*ecdsa.PublicKey)
	request, _ := http.NewRequest(fixture.Method, fixture.Target, nil)
	request.Header = fixture.Request
	body, _ := base64.StdEncoding.DecodeString(fixture.Body)
	result, _ := base64.StdEncoding.DecodeString(fixture.ResponseBody)
	if _, _, e = verifyMessage(fixture.Request, request, 0, body, fixture.Identity, key, time.Unix(fixture.Now, 0)); e != nil {
		t.Fatal(e)
	}
	if _, _, e = verifyMessage(fixture.Response, request, 200, result, fixture.Identity, key, time.Unix(fixture.Now, 0)); e != nil {
		t.Fatal(e)
	}
}
