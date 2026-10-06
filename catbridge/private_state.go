package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func (b *Bridge) jobKey() ([]byte, error) {
	path := filepath.Join(b.directory, "job-key.bin")
	key, e := os.ReadFile(path)
	if e == nil {
		if len(key) != 32 {
			return nil, errors.New("E_IDENTITY")
		}
		return key, nil
	}
	if !os.IsNotExist(e) {
		return nil, e
	}
	key = make([]byte, 32)
	if _, e = rand.Read(key); e != nil {
		return nil, e
	}
	file, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if os.IsExist(e) {
		return b.jobKey()
	}
	if e != nil {
		return nil, e
	}
	defer file.Close()
	if _, e = file.Write(key); e != nil {
		return nil, e
	}
	if e = file.Sync(); e != nil {
		return nil, e
	}
	return key, nil
}
func (b *Bridge) writePrivate(path string, value any) error {
	key, e := b.jobKey()
	if e != nil {
		return e
	}
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()
	block, e := aes.NewCipher(key)
	if e != nil {
		return e
	}
	aead, e := cipher.NewGCM(block)
	if e != nil {
		return e
	}
	plain, e := json.Marshal(value)
	if e != nil {
		return e
	}
	defer func() {
		for i := range plain {
			plain[i] = 0
		}
	}()
	nonce := make([]byte, aead.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	sealed := append(nonce, aead.Seal(nil, nonce, plain, []byte(filepath.Base(path)))...)
	return writeJSON(path, map[string]any{"format": "catbridge-state", "version": 2, "ciphertext": base64.StdEncoding.EncodeToString(sealed)})
}
func (b *Bridge) readPrivate(path string, value any) error {
	file, e := os.Open(path)
	if e != nil {
		return e
	}
	defer file.Close()
	bytes, e := io.ReadAll(io.LimitReader(file, 2*1024*1024+1))
	if e != nil || len(bytes) > 2*1024*1024 {
		return errors.New("E_SIZE")
	}
	var envelope struct {
		Format     string `json:"format"`
		Version    int    `json:"version"`
		Ciphertext string `json:"ciphertext"`
	}
	if json.Unmarshal(bytes, &envelope) != nil {
		return errors.New("E_STORAGE")
	}
	if envelope.Format == "" {
		return json.Unmarshal(bytes, value)
	}
	if envelope.Format != "catbridge-state" || envelope.Version != 2 {
		return errors.New("E_VERSION")
	}
	wire, e := base64.StdEncoding.Strict().DecodeString(envelope.Ciphertext)
	if e != nil {
		return errors.New("E_STORAGE")
	}
	key, e := b.jobKey()
	if e != nil {
		return e
	}
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()
	block, e := aes.NewCipher(key)
	if e != nil {
		return e
	}
	aead, e := cipher.NewGCM(block)
	if e != nil {
		return e
	}
	if len(wire) < aead.NonceSize()+aead.Overhead() {
		return errors.New("E_STORAGE")
	}
	plain, e := aead.Open(nil, wire[:aead.NonceSize()], wire[aead.NonceSize():], []byte(filepath.Base(path)))
	if e != nil {
		return errors.New("E_STORAGE")
	}
	defer func() {
		for i := range plain {
			plain[i] = 0
		}
	}()
	if strings.Contains(string(plain), "\x00") {
		return errors.New("E_STORAGE")
	}
	return json.Unmarshal(plain, value)
}
