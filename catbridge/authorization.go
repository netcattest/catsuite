package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"time"
)

type Authorization struct {
	Protocol   int    `json:"protocol"`
	Device     string `json:"device"`
	Task       string `json:"task"`
	Flow       string `json:"flow"`
	Revision   string `json:"revision"`
	Node       string `json:"node"`
	Capability string `json:"capability"`
	Definition string `json:"definition"`
	Expires    int64  `json:"expires"`
}

func jobDefinition(input JobRequest) string {
	input.Authorization = ""
	input.RetryUnknown = false
	bytes, _ := json.Marshal(input)
	return hash(bytes)
}
func (b *Bridge) authorize(w http.ResponseWriter, r *http.Request) {
	owner, e := b.owner(r)
	if e != nil {
		fail(w, 403, "E_PAIRING_REVOKED")
		return
	}
	var input JobRequest
	if decode(w, r, &input) != nil {
		fail(w, 400, "E_JOB")
		return
	}
	if _, e = b.validateJob(input); e != nil {
		fail(w, 403, e.Error())
		return
	}
	if input.Resource != "" {
		if _, e = b.resourceFor(input, owner); e != nil {
			fail(w, 403, e.Error())
			return
		}
	}
	grant := Authorization{Protocol: 2, Device: owner, Task: input.ID, Flow: input.Flow, Revision: input.Revision, Node: input.Node, Capability: input.Capability, Definition: jobDefinition(input), Expires: time.Now().Unix() + 600}
	payload, _ := json.Marshal(grant)
	digest := sha256.Sum256(payload)
	key := b.serverCertificate.PrivateKey.(*ecdsa.PrivateKey)
	a, c, e := ecdsa.Sign(rand.Reader, key, digest[:])
	if e != nil {
		fail(w, 500, "E_SIGNATURE")
		return
	}
	wire := make([]byte, 64)
	a.FillBytes(wire[:32])
	c.FillBytes(wire[32:])
	response(w, 200, map[string]any{"authorization": base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(wire), "claims": grant})
}
func (b *Bridge) verifyAuthorization(input JobRequest, owner string) error {
	parts := strings.Split(input.Authorization, ".")
	if len(parts) != 2 || len(input.Authorization) > 4096 {
		return errors.New("E_AUTHORIZATION")
	}
	payload, e := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if e != nil {
		return errors.New("E_AUTHORIZATION")
	}
	wire, e := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if e != nil || len(wire) != 64 {
		return errors.New("E_AUTHORIZATION")
	}
	digest := sha256.Sum256(payload)
	key := b.serverCertificate.PrivateKey.(*ecdsa.PrivateKey)
	if !ecdsa.Verify(&key.PublicKey, digest[:], new(big.Int).SetBytes(wire[:32]), new(big.Int).SetBytes(wire[32:])) {
		return errors.New("E_AUTHORIZATION")
	}
	var grant Authorization
	if json.Unmarshal(payload, &grant) != nil || grant.Protocol != 2 || grant.Expires <= time.Now().Unix() || grant.Expires > time.Now().Unix()+600 || grant.Device != owner || grant.Task != input.ID || grant.Flow != input.Flow || grant.Revision != input.Revision || grant.Node != input.Node || grant.Capability != input.Capability || grant.Definition != jobDefinition(input) {
		return errors.New("E_AUTHORIZATION")
	}
	return nil
}
