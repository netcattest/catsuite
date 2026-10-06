package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"path"
	"regexp"
	"slices"
	"strings"
)

type SnapshotFile struct {
	Path   string `json:"path"`
	Data   string `json:"data"`
	SHA256 string `json:"sha256"`
}
type EcosystemResource struct {
	Kind  string         `json:"kind"`
	Words []string       `json:"words,omitempty"`
	Files []SnapshotFile `json:"files,omitempty"`
	Token string         `json:"token,omitempty"`
}

func resourceKindValid(kind string) bool {
	return slices.Contains([]string{"", "openapi", "wordlist", "snapshot", "jwt"}, kind)
}
func ecosystemResourceDocument(data []byte, kind string) (EcosystemResource, error) {
	var value EcosystemResource
	if len(data) < 1 || len(data) > 2*1024*1024 {
		return value, errors.New("E_SIZE")
	}
	depth, quoted, escaped := 0, false, false
	for _, c := range data {
		if quoted {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				quoted = false
			}
			continue
		}
		if c == '"' {
			quoted = true
		} else if c == '{' || c == '[' {
			depth++
			if depth > 16 {
				return value, errors.New("E_SIZE")
			}
		} else if c == '}' || c == ']' {
			depth--
		}
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || value.Kind != kind {
		return value, errors.New("E_RESOURCE")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return value, errors.New("E_RESOURCE")
	}
	switch kind {
	case "wordlist":
		if len(value.Words) < 2 || len(value.Words) > 500 || len(value.Files) > 0 || value.Token != "" {
			return value, errors.New("E_RESOURCE")
		}
		seen := map[string]bool{}
		for _, word := range value.Words {
			if len(word) > 128 || !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_./-]*$`).MatchString(word) || strings.Contains(word, "..") || seen[word] {
				return value, errors.New("E_RESOURCE")
			}
			seen[word] = true
		}
	case "snapshot":
		if len(value.Files) < 1 || len(value.Files) > 100 || len(value.Words) > 0 || value.Token != "" {
			return value, errors.New("E_RESOURCE")
		}
		seen := map[string]bool{}
		total := 0
		for _, file := range value.Files {
			if file.Path == "" || file.Path == "." || len(file.Path) > 180 || strings.HasPrefix(file.Path, "/") || path.Clean(file.Path) != file.Path || strings.Contains(file.Path, "..") || !regexp.MustCompile(`^[A-Za-z0-9_.][A-Za-z0-9_./-]*$`).MatchString(file.Path) || seen[file.Path] {
				return value, errors.New("E_PATH")
			}
			seen[file.Path] = true
			decoded, e := base64.StdEncoding.Strict().DecodeString(file.Data)
			total += len(decoded)
			if e != nil || len(decoded) > 256*1024 || total > 1024*1024 || hash(decoded) != file.SHA256 {
				return value, errors.New("E_INTEGRITY")
			}
		}
	case "jwt":
		if len(value.Files) > 0 || len(value.Words) > 0 || len(value.Token) > 16384 || !regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$`).MatchString(value.Token) {
			return value, errors.New("E_RESOURCE")
		}
	default:
		return value, errors.New("E_RESOURCE")
	}
	return value, nil
}
