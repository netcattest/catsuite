package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var numericPattern = regexp.MustCompile(`^[0-9]{24}$`)

type pairWindow struct {
	Until int64
	Count int
}

func numericCode() (string, error) {
	value, e := rand.Int(rand.Reader, new(big.Int).Exp(big.NewInt(10), big.NewInt(24), nil))
	if e != nil {
		return "", e
	}
	text := value.String()
	return strings.Repeat("0", 24-len(text)) + text, nil
}

func pairingProof(code, target, challenge string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(code))
	mac.Write([]byte("CATBRIDGE-NUMERIC-1\nGET\n" + target + "\n" + challenge + "\n" + hash(body)))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (b *Bridge) numericInfo(r *http.Request) (Pairing, error) {
	if len(r.Header.Values("X-Cat-Pair-Key")) != 1 || len(r.Header.Get("X-Cat-Pair-Key")) > 256 {
		return Pairing{}, errors.New("E_SIGNATURE")
	}
	der, e := base64.StdEncoding.Strict().DecodeString(r.Header.Get("X-Cat-Pair-Key"))
	if e != nil {
		return Pairing{}, errors.New("E_SIGNATURE")
	}
	parsed, e := x509.ParsePKIXPublicKey(der)
	key, ok := parsed.(*ecdsa.PublicKey)
	if e != nil || !ok || key.Curve != elliptic.P256() {
		return Pairing{}, errors.New("E_SIGNATURE")
	}
	if _, _, e = verifyMessage(r.Header, r, 0, nil, r.Header.Get("X-Cat-Device"), key, time.Now()); e != nil {
		return Pairing{}, e
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now().Unix()
	if b.pairWindows == nil {
		b.pairWindows = map[string]pairWindow{}
		b.pairChallenges = map[string]int64{}
	}
	for key, window := range b.pairWindows {
		if window.Until <= now {
			delete(b.pairWindows, key)
		}
	}
	for key, expiry := range b.pairChallenges {
		if expiry <= now {
			delete(b.pairChallenges, key)
		}
	}
	address, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil {
		return Pairing{}, errors.New("E_PAIRING")
	}
	for _, key := range []string{"all", "ip:" + address} {
		window := b.pairWindows[key]
		limit := 16
		if key == "all" {
			limit = 128
		}
		if window.Count >= limit || len(b.pairWindows) >= 1024 {
			return Pairing{}, errors.New("E_PAIRING_RATE")
		}
		window.Count++
		if window.Until == 0 {
			window.Until = now + 60
		}
		b.pairWindows[key] = window
	}
	challenge := r.Header.Get("X-Cat-Pair-Challenge")
	if !messagePattern.MatchString(challenge) || r.Header.Get("X-Cat-Message") != challenge || len(r.Header.Values("X-Cat-Pair-Challenge")) != 1 || len(r.Header.Values("X-Cat-Message")) != 1 || messageTarget(r) != b.publicURL+"/v2/pair/info" || r.ContentLength > 0 {
		return Pairing{}, errors.New("E_PAIRING")
	}
	if _, exists := b.pairChallenges[challenge]; exists {
		return Pairing{}, errors.New("E_REPLAY")
	}
	b.pairChallenges[challenge] = now + 60
	var pairing Pairing
	if readJSON(filepath.Join(b.directory, "pairing.json"), &pairing) != nil || pairing.Protocol != 2 || pairing.Expires <= time.Now().UnixMilli() || !numericPattern.MatchString(pairing.Code) || pairing.URL != b.publicURL || pairing.Fingerprint != hash(b.serverCertificate.Certificate[0]) {
		return Pairing{}, errors.New("E_PAIRING_EXPIRED")
	}
	return pairing, nil
}

func (b *Bridge) numericHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/pair/info" {
			next.ServeHTTP(w, r)
			return
		}
		out := &bufferedResponse{header: make(http.Header)}
		if r.Method != "GET" || r.URL.RawQuery != "" {
			fail(out, 400, "E_PAIRING")
		} else {
			pairing, e := b.numericInfo(r)
			if e != nil {
				status := 403
				if e.Error() == "E_PAIRING_RATE" {
					status = 429
				}
				fail(out, status, e.Error())
			} else {
				response(out, 200, map[string]any{"protocol": 2, "url": pairing.URL, "fingerprint": pairing.Fingerprint, "expires": pairing.Expires, "name": pairing.Name})
				out.header.Set("X-Cat-Pair-Proof", pairingProof(pairing.Code, messageTarget(r), r.Header.Get("X-Cat-Pair-Challenge"), out.body.Bytes()))
			}
		}
		key, ok := b.serverCertificate.PrivateKey.(*ecdsa.PrivateKey)
		if !ok || signMessage(out.header, r, out.code, out.body.Bytes(), hash(b.serverCertificate.Certificate[0]), key, time.Now()) != nil {
			http.Error(w, "E_IDENTITY", 500)
			return
		}
		out.header.Set("Cache-Control", "no-store")
		for name, values := range out.header {
			w.Header()[name] = values
		}
		w.WriteHeader(out.code)
		w.Write(out.body.Bytes())
	})
}

func verifyPairingProof(code, target, challenge string, body []byte, proof string) bool {
	if !numericPattern.MatchString(code) || !messagePattern.MatchString(challenge) || !json.Valid(body) {
		return false
	}
	return hmac.Equal([]byte(proof), []byte(pairingProof(code, target, challenge, body)))
}
