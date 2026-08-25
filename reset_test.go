package main

import "testing"

// A correct one's-complement checksum has a well-known self-check
// property: summing all 16-bit words of the header *including* the
// checksum field itself, with end-around carry, always yields 0xFFFF.
// This catches checksum bugs without needing an external reference value.
func TestFinalizeChecksumsSelfConsistent(t *testing.T) {
	srcIP := [4]byte{10, 0, 0, 5}
	dstIP := [4]byte{93, 184, 216, 34}

	pkt := buildResetPacket(srcIP, dstIP, 51234, 443, 1000, 2000)
	finalizeChecksums(pkt)

	ipSum := onesComplementSumCarry(0, pkt[0:20])
	if finishChecksum(ipSum) != 0 {
		t.Fatalf("IP header checksum self-check failed: got residual %#x, want 0", finishChecksum(ipSum))
	}

	var pseudo [12]byte
	copy(pseudo[0:4], pkt[12:16])
	copy(pseudo[4:8], pkt[16:20])
	pseudo[9] = 6
	pseudo[10] = 0
	pseudo[11] = 20 // TCP segment length, no options

	sum := onesComplementSumCarry(0, pseudo[:])
	sum = onesComplementSumCarry(sum, pkt[20:40])
	if finishChecksum(sum) != 0 {
		t.Fatalf("TCP checksum self-check failed: got residual %#x, want 0", finishChecksum(sum))
	}
}

func TestBuildResetPacketFields(t *testing.T) {
	srcIP := [4]byte{1, 2, 3, 4}
	dstIP := [4]byte{5, 6, 7, 8}
	pkt := buildResetPacket(srcIP, dstIP, 1111, 2222, 100, 200)

	if pkt[0] != 0x45 {
		t.Errorf("version/IHL byte = %#x, want 0x45", pkt[0])
	}
	if pkt[9] != 6 {
		t.Errorf("protocol byte = %d, want 6 (TCP)", pkt[9])
	}
	if got := [4]byte{pkt[12], pkt[13], pkt[14], pkt[15]}; got != srcIP {
		t.Errorf("src IP = %v, want %v", got, srcIP)
	}
	if got := [4]byte{pkt[16], pkt[17], pkt[18], pkt[19]}; got != dstIP {
		t.Errorf("dst IP = %v, want %v", got, dstIP)
	}
	if tcp := pkt[20:]; tcp[13] != (0x04 | 0x10) {
		t.Errorf("TCP flags byte = %#x, want RST|ACK (0x14)", tcp[13])
	}
}
