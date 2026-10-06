package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func numericFixture(t *testing.T) (*Bridge, string, *http.Client, string) {
	t.Helper()
	b, server, client := setupBridge(t)
	b.publicURL = server.URL
	code, e := numericCode()
	if e != nil {
		t.Fatal(e)
	}
	pair := Pairing{Protocol: 2, URL: server.URL, Fingerprint: hash(b.serverCertificate.Certificate[0]), Code: code, Expires: time.Now().Add(time.Minute).UnixMilli(), Name: "CatBridge"}
	if e = writeJSON(filepath.Join(b.directory, "pairing.json"), pair); e != nil {
		t.Fatal(e)
	}
	return b, server.URL, client, code
}

func numericRequest(t *testing.T, client *http.Client, target, challenge string) (int, []byte, http.Header) {
	t.Helper()
	req, _ := http.NewRequest("GET", target, nil)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	req.Header.Set("X-Cat-Pair-Key", base64.StdEncoding.EncodeToString(der))
	if e := signMessage(req.Header, req, 0, nil, testID, key, time.Now(), challenge); e != nil {
		t.Fatal(e)
	}
	req.Header.Set("X-Cat-Pair-Challenge", challenge)
	req.Header.Set("X-Cat-Message", challenge)
	res, e := client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	defer res.Body.Close()
	body, e := io.ReadAll(res.Body)
	if e != nil {
		t.Fatal(e)
	}
	leaf := res.TLS.PeerCertificates[0]
	if _, _, e = verifyMessage(res.Header, req, res.StatusCode, body, hash(leaf.Raw), leaf.PublicKey.(*ecdsa.PublicKey), time.Now()); e != nil {
		t.Fatal(e)
	}
	return res.StatusCode, body, res.Header
}

func TestNumericPairingIdentityAndSingleUse(t *testing.T) {
	b, base, client, code := numericFixture(t)
	challenge := randomCode()
	status, body, headers := numericRequest(t, client, base+"/v2/pair/info", challenge)
	if status != 200 || strings.Contains(string(body), code) || !verifyPairingProof(code, base+"/v2/pair/info", challenge, body, headers.Get("X-Cat-Pair-Proof")) {
		t.Fatal(status, string(body))
	}
	for _, change := range []struct {
		code, target, challenge string
		body                    []byte
	}{
		{strings.Repeat("0", 24), base + "/v2/pair/info", challenge, body},
		{code, base + "/v2/jobs", challenge, body},
		{code, base + "/v2/pair/info", randomCode(), body},
		{code, base + "/v2/pair/info", challenge, []byte(`{"protocol":1}`)},
	} {
		if verifyPairingProof(change.code, change.target, change.challenge, change.body, headers.Get("X-Cat-Pair-Proof")) {
			t.Fatal("tampering accepted")
		}
	}
	if status, _, _ := numericRequest(t, client, base+"/v2/pair/info", challenge); status != 403 {
		t.Fatal("challenge reused")
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: testID}}, key)
	testKeys[client] = key
	t.Cleanup(func() { delete(testKeys, client) })
	status, result := requestTest(t, client, "POST", base+"/v2/pair", map[string]string{"id": testID, "code": code, "csr": base64.StdEncoding.EncodeToString(csr)})
	if status != 200 {
		t.Fatal(status, result)
	}
	keyBytes, _ := x509.MarshalECPrivateKey(key)
	cert, e := tls.X509KeyPair([]byte(result["certificate"].(string)), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}))
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	pool.AddCert(b.ca)
	paired := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}}, Timeout: 3 * time.Second}
	testKeys[paired] = key
	t.Cleanup(func() { paired.CloseIdleConnections(); delete(testKeys, paired) })
	if status, _ = requestTest(t, paired, "GET", base+"/v2/capabilities", nil); status != 200 {
		t.Fatal("mTLS unavailable")
	}
	if status, _, _ := numericRequest(t, client, base+"/v2/pair/info", randomCode()); status != 403 {
		t.Fatal("consumed code exposed")
	}
}

func TestNumericPairingBoundsAndRate(t *testing.T) {
	for i := 0; i < 100; i++ {
		code, e := numericCode()
		if e != nil || !numericPattern.MatchString(code) {
			t.Fatal(code, e)
		}
	}
	b, base, client, _ := numericFixture(t)
	for i := 0; i < 16; i++ {
		status, _, _ := numericRequest(t, client, base+"/v2/pair/info", randomCode())
		if status != 200 {
			t.Fatal(i, status)
		}
	}
	if status, _, _ := numericRequest(t, client, base+"/v2/pair/info", randomCode()); status != 429 {
		t.Fatal(status)
	}
	b.mu.Lock()
	b.pairWindows = nil
	b.mu.Unlock()
	var pair Pairing
	readJSON(filepath.Join(b.directory, "pairing.json"), &pair)
	pair.Expires = time.Now().Add(-time.Second).UnixMilli()
	writeJSON(filepath.Join(b.directory, "pairing.json"), pair)
	if status, _, _ := numericRequest(t, client, base+"/v2/pair/info", randomCode()); status != 403 {
		t.Fatal("expired")
	}
}

func TestNumericPairingCrossLanguageVector(t *testing.T) {
	var v struct{ Code, Target, Challenge, Body, Proof string }
	bytes, e := os.ReadFile("testdata/pairing-numeric.json")
	if e != nil || json.Unmarshal(bytes, &v) != nil {
		t.Fatal(e)
	}
	if pairingProof(v.Code, v.Target, v.Challenge, []byte(v.Body)) != v.Proof {
		t.Fatal("vector mismatch")
	}
}

func TestNumericBootstrapRejectsUnsignedAndTamperedRequests(t *testing.T) {
	_, base, client, _ := numericFixture(t)
	if status, _ := requestTest(t, client, "GET", base+"/v2/pair/info", nil); status != 403 {
		t.Fatal("unsigned bootstrap accepted")
	}
	for _, mutation := range []string{"key", "identity", "digest", "method"} {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
		req, _ := http.NewRequest("GET", base+"/v2/pair/info", nil)
		challenge := randomCode()
		req.Header.Set("X-Cat-Pair-Key", base64.StdEncoding.EncodeToString(der))
		req.Header.Set("X-Cat-Pair-Challenge", challenge)
		signMessage(req.Header, req, 0, nil, testID, key, time.Now(), challenge)
		switch mutation {
		case "key":
			other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			der, _ := x509.MarshalPKIXPublicKey(&other.PublicKey)
			req.Header.Set("X-Cat-Pair-Key", base64.StdEncoding.EncodeToString(der))
		case "identity":
			req.Header.Set("X-Cat-Device", "other-device")
		case "digest":
			req.Header.Set("Content-Digest", contentDigest([]byte("changed")))
		case "method":
			req.Method = "POST"
		}
		res, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode < 400 || res.Header.Get("X-Cat-Pair-Proof") != "" {
			t.Fatal("tampered bootstrap accepted", mutation, string(body))
		}
	}
}
