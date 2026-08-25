package main

import (
	"bytes"
	"encoding/binary"
)

// extractSNI pulls the server_name (SNI) extension out of a TLS ClientHello.
// Only handles the common case where the whole ClientHello fits in one TCP
// segment (true for almost all real clients — browsers send ~200-500 bytes).
// Every read is bounds-checked; malformed/truncated input just returns "".
func extractSNI(payload []byte) string {
	defer func() { recover() }() // belt-and-braces against any slip in the bounds checks below

	// TLS record header: ContentType(1) Version(2) Length(2)
	if len(payload) < 6 || payload[0] != 0x16 {
		return "" // not a Handshake record
	}
	pos := 5

	// Handshake header: HandshakeType(1) Length(3)
	if len(payload) < pos+4 || payload[pos] != 0x01 {
		return "" // not a ClientHello
	}
	pos += 4

	// ClientVersion(2) + Random(32)
	pos += 34
	if len(payload) < pos+1 {
		return ""
	}

	// SessionID
	sidLen := int(payload[pos])
	pos++
	pos += sidLen
	if len(payload) < pos+2 {
		return ""
	}

	// CipherSuites
	csLen := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
	pos += 2 + csLen
	if len(payload) < pos+1 {
		return ""
	}

	// CompressionMethods
	cmLen := int(payload[pos])
	pos++
	pos += cmLen
	if len(payload) < pos+2 {
		return "" // no extensions present
	}

	// Extensions
	extTotalLen := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
	pos += 2
	end := pos + extTotalLen
	if end > len(payload) {
		end = len(payload)
	}

	for pos+4 <= end {
		extType := binary.BigEndian.Uint16(payload[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(payload[pos+2 : pos+4]))
		pos += 4
		if pos+extLen > end {
			return ""
		}

		if extType == 0x0000 { // server_name
			data := payload[pos : pos+extLen]
			if len(data) < 5 {
				return ""
			}
			// ServerNameList: ListLength(2) then NameType(1) NameLength(2) Name(...)
			if data[2] != 0x00 { // host_name
				return ""
			}
			nameLen := int(binary.BigEndian.Uint16(data[3:5]))
			if 5+nameLen > len(data) {
				return ""
			}
			return string(data[5 : 5+nameLen])
		}

		pos += extLen
	}

	return ""
}

var httpHostMarker = []byte("\r\nHost: ")

// extractHost pulls the Host header out of a plaintext HTTP request.
// Assumes (like the request line itself) that it's present in the first
// packet of the request.
func extractHost(payload []byte) string {
	if !bytes.HasPrefix(payload, []byte("GET ")) && !bytes.HasPrefix(payload, []byte("POST ")) &&
		!bytes.HasPrefix(payload, []byte("PUT ")) && !bytes.HasPrefix(payload, []byte("HEAD ")) &&
		!bytes.HasPrefix(payload, []byte("CONNECT ")) {
		return ""
	}

	idx := bytes.Index(payload, httpHostMarker)
	if idx < 0 {
		return ""
	}
	start := idx + len(httpHostMarker)
	end := bytes.IndexByte(payload[start:], '\r')
	if end < 0 {
		return ""
	}
	return string(payload[start : start+end])
}
