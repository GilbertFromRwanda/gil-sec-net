package main

import (
	"encoding/binary"
	"net"
)

// maxPacketSize is a generous upper bound for a single captured IP packet,
// shared by every platform's capture buffer (WinDivert's own
// WINDIVERT_MTU_MAX is 40 + 0xFFFF; NFQUEUE/divert sockets don't hand back
// anything larger than the interface MTU either).
const maxPacketSize = 40 + 0xFFFF

// parsedPacket holds the fields we need out of a captured IPv4/TCP packet.
// WINDIVERT_IPHDR/WINDIVERT_TCPHDR are literally the standard wire-format
// headers (RFC 791 / RFC 793), so we parse them by hand instead of binding
// WinDivertHelperParsePacket.
type parsedPacket struct {
	srcIP     net.IP
	dstIP     net.IP
	srcPort   uint16
	dstPort   uint16
	seq       uint32
	ack       uint32
	ipHdrLen  int
	tcpHdrLen int
	payload   []byte
}

// parseIPv4TCP returns ok=false for anything that isn't a well-formed
// IPv4/TCP packet with a fully-present header — captured traffic is
// untrusted input, so every length is bounds-checked before use.
func parseIPv4TCP(packet []byte) (parsedPacket, bool) {
	var p parsedPacket
	if len(packet) < 20 {
		return p, false
	}

	version := packet[0] >> 4
	if version != 4 {
		return p, false
	}
	ipHdrLen := int(packet[0]&0x0F) * 4
	if ipHdrLen < 20 || len(packet) < ipHdrLen {
		return p, false
	}
	protocol := packet[9]
	if protocol != 6 { // TCP
		return p, false
	}

	if len(packet) < ipHdrLen+20 {
		return p, false
	}
	tcp := packet[ipHdrLen:]
	tcpHdrLen := int(tcp[12]>>4) * 4
	if tcpHdrLen < 20 || len(packet) < ipHdrLen+tcpHdrLen {
		return p, false
	}

	p.srcIP = net.IPv4(packet[12], packet[13], packet[14], packet[15])
	p.dstIP = net.IPv4(packet[16], packet[17], packet[18], packet[19])
	p.srcPort = binary.BigEndian.Uint16(tcp[0:2])
	p.dstPort = binary.BigEndian.Uint16(tcp[2:4])
	p.seq = binary.BigEndian.Uint32(tcp[4:8])
	p.ack = binary.BigEndian.Uint32(tcp[8:12])
	p.ipHdrLen = ipHdrLen
	p.tcpHdrLen = tcpHdrLen
	p.payload = packet[ipHdrLen+tcpHdrLen:]

	return p, true
}
