package main

import (
	"encoding/binary"
	"testing"
)

// buildClientHello constructs a minimal-but-real TLS ClientHello record
// carrying a server_name (SNI) extension, to exercise extractSNI without
// needing a live network capture.
func buildClientHello(sni string) []byte {
	var ext []byte
	sniList := append([]byte{0x00}, put16(uint16(len(sni)))...)
	sniList = append(sniList, []byte(sni)...)
	sniListWithLen := append(put16(uint16(len(sniList))), sniList...)
	ext = append(ext, 0x00, 0x00) // extension type: server_name
	ext = append(ext, put16(uint16(len(sniListWithLen)))...)
	ext = append(ext, sniListWithLen...)

	var body []byte
	body = append(body, 0x03, 0x03)          // ClientVersion
	body = append(body, make([]byte, 32)...) // Random
	body = append(body, 0x00)                // SessionID length = 0
	body = append(body, put16(2)...)         // CipherSuites length
	body = append(body, 0x00, 0x00)          // one cipher suite
	body = append(body, 0x01)                // CompressionMethods length
	body = append(body, 0x00)                // null compression
	body = append(body, put16(uint16(len(ext)))...)
	body = append(body, ext...)

	handshake := append([]byte{0x01}, put24(uint32(len(body)))...)
	handshake = append(handshake, body...)

	record := append([]byte{0x16, 0x03, 0x01}, put16(uint16(len(handshake)))...)
	record = append(record, handshake...)
	return record
}

func put16(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}

func put24(v uint32) []byte {
	return []byte{byte(v >> 16), byte(v >> 8), byte(v)}
}

func TestExtractSNI(t *testing.T) {
	pkt := buildClientHello("cloudflare-eth.com")
	got := extractSNI(pkt)
	if got != "cloudflare-eth.com" {
		t.Fatalf("extractSNI() = %q, want %q", got, "cloudflare-eth.com")
	}
}

func TestExtractSNITruncated(t *testing.T) {
	pkt := buildClientHello("cloudflare-eth.com")
	for _, cut := range []int{0, 1, 5, 6, 10, 40, len(pkt) - 3, len(pkt) - 1} {
		if cut > len(pkt) {
			continue
		}
		// Must never panic on truncated/malformed input.
		extractSNI(pkt[:cut])
	}
}

func TestExtractSNINotHandshake(t *testing.T) {
	if got := extractSNI([]byte{0x17, 0x03, 0x03, 0x00, 0x01, 0xAA}); got != "" {
		t.Fatalf("extractSNI() on non-handshake record = %q, want \"\"", got)
	}
}

func TestExtractHost(t *testing.T) {
	req := "GET /v1/foo HTTP/1.1\r\nHost: cloudflare-eth.com\r\nUser-Agent: test\r\n\r\n"
	if got := extractHost([]byte(req)); got != "cloudflare-eth.com" {
		t.Fatalf("extractHost() = %q, want %q", got, "cloudflare-eth.com")
	}
}

func TestExtractHostNoMatch(t *testing.T) {
	if got := extractHost([]byte("not an http request")); got != "" {
		t.Fatalf("extractHost() = %q, want \"\"", got)
	}
}

func TestBlocklistMatch(t *testing.T) {
	b := &blocklist{domains: []string{"cloudflare-eth.com", "infura.io"}}

	cases := map[string]string{
		"cloudflare-eth.com":          "cloudflare-eth.com",
		"CloudFlare-Eth.com":          "cloudflare-eth.com", // case-insensitive
		"mainnet.infura.io":           "infura.io",          // subdomain match
		"notcloudflare-eth.com":       "",                   // must not match as substring
		"cloudflare-eth.com.evil.com": "",                   // must not match as prefix
		"example.com":                 "",
	}
	for host, want := range cases {
		if got := b.match(host); got != want {
			t.Errorf("match(%q) = %q, want %q", host, got, want)
		}
	}
}
