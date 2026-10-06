package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const requestComponents = `("@method" "@target-uri" "content-digest" "content-type" "x-cat-protocol" "x-cat-device" "x-cat-message" "x-cat-request")`
const responseComponents = `("@status" "@method";req "@target-uri";req "content-digest" "content-type" "x-cat-protocol" "x-cat-device" "x-cat-message" "x-cat-request")`

var signatureParameters = regexp.MustCompile(`^;created=([0-9]{1,12});expires=([0-9]{1,12});nonce="([A-Za-z0-9_-]{43})";keyid="([a-zA-Z0-9-]{1,64})";alg="ecdsa-p256-sha256"$`)
var messagePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

func messageTarget(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil && r.URL.Scheme != "" {
		scheme = r.URL.Scheme
	}
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	return scheme + "://" + host + r.URL.RequestURI()
}
func contentDigest(body []byte) string {
	digest := sha256.Sum256(body)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(digest[:]) + ":"
}
func signatureBase(h http.Header, r *http.Request, status int, parameters string) string {
	var lines []string
	if status == 0 {
		lines = []string{`"@method": ` + r.Method, `"@target-uri": ` + messageTarget(r)}
	} else {
		lines = []string{`"@status": ` + strconv.Itoa(status), `"@method";req: ` + r.Method, `"@target-uri";req: ` + messageTarget(r)}
	}
	for _, name := range []string{"content-digest", "content-type", "x-cat-protocol", "x-cat-device", "x-cat-message", "x-cat-request"} {
		lines = append(lines, `"`+name+`": `+h.Get(name))
	}
	return strings.Join(append(lines, `"@signature-params": `+parameters), "\n")
}
func signMessage(h http.Header, r *http.Request, status int, body []byte, identity string, key *ecdsa.PrivateKey, now time.Time, message ...string) error {
	if len(message) > 1 || (len(message) == 1 && !messagePattern.MatchString(message[0])) {
		return errors.New("E_SIGNATURE")
	}
	h.Set("Content-Digest", contentDigest(body))
	h.Set("Content-Type", "application/json")
	h.Set("X-Cat-Protocol", "2")
	h.Set("X-Cat-Device", identity)
	h.Set("X-Cat-Message", randomCode())
	if len(message) == 1 {
		h.Set("X-Cat-Message", message[0])
	}
	h.Set("X-Cat-Request", "none")
	components := requestComponents
	if status != 0 {
		components = responseComponents
		h.Set("X-Cat-Request", r.Header.Get("X-Cat-Message"))
	}
	parameters := components + `;created=` + strconv.FormatInt(now.Unix(), 10) + `;expires=` + strconv.FormatInt(now.Unix()+60, 10) + `;nonce="` + randomCode() + `";keyid="` + identity + `";alg="ecdsa-p256-sha256"`
	digest := sha256.Sum256([]byte(signatureBase(h, r, status, parameters)))
	a, b, e := ecdsa.Sign(rand.Reader, key, digest[:])
	if e != nil {
		return e
	}
	wire := make([]byte, 64)
	a.FillBytes(wire[:32])
	b.FillBytes(wire[32:])
	h.Set("Signature-Input", "cat="+parameters)
	h.Set("Signature", "cat=:"+base64.StdEncoding.EncodeToString(wire)+":")
	return nil
}
func verifyMessage(h http.Header, r *http.Request, status int, body []byte, identity string, key *ecdsa.PublicKey, now time.Time) (string, int64, error) {
	components := requestComponents
	if status != 0 {
		components = responseComponents
	}
	input := h.Get("Signature-Input")
	if !strings.HasPrefix(input, "cat="+components) {
		return "", 0, errors.New("E_SIGNATURE")
	}
	params := strings.TrimPrefix(input, "cat=")
	parsed := signatureParameters.FindStringSubmatch(strings.TrimPrefix(params, components))
	if len(parsed) != 5 || parsed[4] != identity || h.Get("X-Cat-Protocol") != "2" || h.Get("X-Cat-Device") != identity || h.Get("Content-Type") != "application/json" || !messagePattern.MatchString(h.Get("X-Cat-Message")) {
		return "", 0, errors.New("E_SIGNATURE")
	}
	for _, name := range []string{"Signature-Input", "Signature", "Content-Digest", "Content-Type", "X-Cat-Protocol", "X-Cat-Device", "X-Cat-Message", "X-Cat-Request"} {
		if len(h.Values(name)) != 1 || strings.ContainsAny(h.Get(name), "\r\n") {
			return "", 0, errors.New("E_SIGNATURE")
		}
	}
	created, _ := strconv.ParseInt(parsed[1], 10, 64)
	expires, _ := strconv.ParseInt(parsed[2], 10, 64)
	if created > now.Unix()+15 || expires <= now.Unix() || expires <= created || expires-created > 60 {
		return "", 0, errors.New("E_SIGNATURE_EXPIRED")
	}
	correlation := "none"
	if status != 0 {
		correlation = r.Header.Get("X-Cat-Message")
	}
	if h.Get("X-Cat-Request") != correlation || subtle.ConstantTimeCompare([]byte(h.Get("Content-Digest")), []byte(contentDigest(body))) != 1 {
		return "", 0, errors.New("E_DIGEST")
	}
	value := h.Get("Signature")
	if !strings.HasPrefix(value, "cat=:") || !strings.HasSuffix(value, ":") {
		return "", 0, errors.New("E_SIGNATURE")
	}
	wire, e := base64.StdEncoding.Strict().DecodeString(value[5 : len(value)-1])
	if e != nil || len(wire) != 64 || key.Curve != elliptic.P256() {
		return "", 0, errors.New("E_SIGNATURE")
	}
	digest := sha256.Sum256([]byte(signatureBase(h, r, status, params)))
	if !ecdsa.Verify(key, digest[:], new(big.Int).SetBytes(wire[:32]), new(big.Int).SetBytes(wire[32:])) {
		return "", 0, errors.New("E_SIGNATURE")
	}
	return parsed[3], expires, nil
}

type replayJournal struct {
	mu      sync.Mutex
	entries map[string]int64
}

func (b *Bridge) acceptMessage(identity, nonce, message string, expires int64) error {
	b.replay.mu.Lock()
	defer b.replay.mu.Unlock()
	entries := map[string]int64{}
	path := filepath.Join(b.directory, "messages-v2.json")
	if e := readJSON(path, &entries); e != nil && !os.IsNotExist(e) {
		return errors.New("E_STORAGE")
	}
	now := time.Now().Unix()
	for id, expiry := range entries {
		if expiry <= now {
			delete(entries, id)
		}
	}
	nonceKey := identity + ":nonce:" + nonce
	messageKey := identity + ":message:" + message
	if entries[nonceKey] > now || entries[messageKey] > now {
		return errors.New("E_REPLAY")
	}
	if len(entries) >= 4000 {
		return errors.New("E_QUEUE")
	}
	entries[nonceKey] = expires
	entries[messageKey] = expires
	if e := writeJSON(path, entries); e != nil {
		return errors.New("E_STORAGE")
	}
	return nil
}

type bufferedResponse struct {
	header http.Header
	code   int
	body   bytes.Buffer
}

func (w *bufferedResponse) Header() http.Header { return w.header }
func (w *bufferedResponse) WriteHeader(code int) {
	if w.code == 0 {
		w.code = code
	}
}
func (w *bufferedResponse) Write(body []byte) (int, error) {
	if w.code == 0 {
		w.code = 200
	}
	if w.body.Len()+len(body) > 1024*1024 {
		return 0, errors.New("E_SIZE")
	}
	return w.body.Write(body)
}

func (b *Bridge) signedHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out := &bufferedResponse{header: make(http.Header)}
		process := func() {
			if !strings.HasPrefix(r.URL.Path, "/v2/") {
				fail(out, 426, "E_PROTOCOL")
				return
			}
			body, e := io.ReadAll(io.LimitReader(r.Body, 256*1024+1))
			if e != nil || len(body) > 256*1024 {
				fail(out, 413, "E_SIZE")
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			identity := r.Header.Get("X-Cat-Device")
			var key *ecdsa.PublicKey
			if r.URL.Path == "/v2/pair" && r.Method == "POST" {
				var input struct {
					ID  string `json:"id"`
					CSR string `json:"csr"`
				}
				if json.Unmarshal(body, &input) != nil || input.ID != identity {
					fail(out, 403, "E_PAIRING")
					return
				}
				der, e := base64.StdEncoding.Strict().DecodeString(input.CSR)
				if e != nil {
					fail(out, 403, "E_PAIRING")
					return
				}
				csr, e := x509.ParseCertificateRequest(der)
				if e != nil || csr.CheckSignature() != nil || csr.Subject.CommonName != identity {
					fail(out, 403, "E_PAIRING")
					return
				}
				key, _ = csr.PublicKey.(*ecdsa.PublicKey)
			} else {
				owner, e := b.owner(r)
				if e != nil || owner != identity {
					fail(out, 403, "E_PAIRING_REVOKED")
					return
				}
				key, _ = r.TLS.PeerCertificates[0].PublicKey.(*ecdsa.PublicKey)
			}
			if key == nil {
				fail(out, 403, "E_SIGNATURE")
				return
			}
			nonce, expires, e := verifyMessage(r.Header, r, 0, body, identity, key, time.Now())
			if e == nil {
				e = b.acceptMessage(identity, nonce, r.Header.Get("X-Cat-Message"), expires)
			}
			if e != nil {
				fail(out, 403, e.Error())
				return
			}
			next.ServeHTTP(out, r)
		}
		process()
		if out.code == 0 {
			out.code = 200
		}
		key, ok := b.serverCertificate.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			http.Error(w, "E_IDENTITY", 500)
			return
		}
		serverID := hash(b.serverCertificate.Certificate[0])
		if e := signMessage(out.header, r, out.code, out.body.Bytes(), serverID, key, time.Now()); e != nil {
			http.Error(w, "E_SIGNATURE", 500)
			return
		}
		for name, values := range out.header {
			w.Header()[name] = values
		}
		w.WriteHeader(out.code)
		w.Write(out.body.Bytes())
	})
}
