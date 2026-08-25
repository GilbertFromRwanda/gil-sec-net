package main

import "encoding/binary"

// buildResetPacket crafts a bare 40-byte IPv4/TCP RST packet, following the
// same technique as WinDivert's official webfilter.c sample. TCP options are
// never included, matching WINDIVERT_IPHDR/WINDIVERT_TCPHDR's plain 20+20
// byte layout.
func buildResetPacket(srcIP, dstIP [4]byte, srcPort, dstPort uint16, seq, ack uint32) []byte {
	pkt := make([]byte, 40)

	// IPv4 header
	pkt[0] = 0x45 // version 4, IHL 5 (20 bytes)
	binary.BigEndian.PutUint16(pkt[2:4], 40)
	pkt[8] = 64 // TTL
	pkt[9] = 6  // protocol = TCP
	copy(pkt[12:16], srcIP[:])
	copy(pkt[16:20], dstIP[:])

	// TCP header
	tcp := pkt[20:40]
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = 5 << 4      // data offset = 5 (20 bytes), no options
	tcp[13] = 0x04 | 0x10 // RST | ACK

	return pkt
}

// finalizeChecksums fills in the IP header and TCP checksums by hand. Only
// needed on Linux/macOS: those inject via a plain IP_HDRINCL raw socket,
// which doesn't compute the TCP checksum for you (and IP checksum
// auto-fill behavior isn't something to rely on across kernel versions).
// The Windows path uses WinDivertHelperCalcChecksums instead and never
// calls this.
func finalizeChecksums(pkt []byte) {
	pkt[10] = 0
	pkt[11] = 0
	ipSum := onesComplementSum(pkt[0:20])
	binary.BigEndian.PutUint16(pkt[10:12], ipSum)

	tcp := pkt[20:40]
	tcp[16] = 0
	tcp[17] = 0

	// Pseudo-header: src(4) dst(4) zero(1) protocol(1) tcpLength(2)
	var pseudo [12]byte
	copy(pseudo[0:4], pkt[12:16])
	copy(pseudo[4:8], pkt[16:20])
	pseudo[9] = 6 // TCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcp)))

	sum := onesComplementSumCarry(0, pseudo[:])
	sum = onesComplementSumCarry(sum, tcp)
	tcpSum := finishChecksum(sum)
	binary.BigEndian.PutUint16(tcp[16:18], tcpSum)
}

func onesComplementSum(data []byte) uint16 {
	return finishChecksum(onesComplementSumCarry(0, data))
}

func onesComplementSumCarry(sum uint32, data []byte) uint32 {
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	return sum
}

func finishChecksum(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}
