package main

import (
	"encoding/json"
	"os"
	"strings"
)

type blocklistFile struct {
	Domains []string `json:"domains"`
}

// blocklist is a case-insensitive exact-or-subdomain matcher, e.g. an entry
// of "infura.io" also matches "mainnet.infura.io".
type blocklist struct {
	domains []string
}

func loadBlocklist(path string) (*blocklist, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f blocklistFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}

	b := &blocklist{}
	for _, d := range f.Domains {
		b.domains = append(b.domains, strings.ToLower(strings.TrimSpace(d)))
	}
	return b, nil
}

// match returns the blocklist entry that matched, or "" if none did.
func (b *blocklist) match(hostname string) string {
	h := strings.ToLower(strings.TrimSpace(hostname))
	if h == "" {
		return ""
	}
	for _, d := range b.domains {
		if h == d || strings.HasSuffix(h, "."+d) {
			return d
		}
	}
	return ""
}
