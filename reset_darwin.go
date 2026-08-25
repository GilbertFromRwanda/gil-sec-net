package main

import "golang.org/x/sys/unix"

// resetSender injects the crafted RST packets built by buildResetPacket
// (shared, in reset.go) via a plain IP_HDRINCL raw socket — standard BSD
// sockets API, not divert-specific, so this part carries much less
// uncertainty than network_darwin.go's divert socket handling.
type resetSender struct {
	fd int
}

func newResetSender() (*resetSender, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return nil, err
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return &resetSender{fd: fd}, nil
}

func (r *resetSender) send(pkt []byte, dst [4]byte) error {
	addr := &unix.SockaddrInet4{Addr: dst}
	return unix.Sendto(r.fd, pkt, 0, addr)
}

// sendResets mirrors the Windows/Linux technique: one RST toward the
// remote server, one spoofed as if from the server toward the local
// client — since the destination there is this machine's own IP, the
// kernel delivers it locally, tearing the socket down immediately.
func (r *resetSender) sendResets(srcIP, dstIP [4]byte, srcPort, dstPort uint16, seq, ack, payloadLen uint32) {
	toServer := buildResetPacket(srcIP, dstIP, srcPort, dstPort, seq, ack)
	finalizeChecksums(toServer)
	r.send(toServer, dstIP)

	toClient := buildResetPacket(dstIP, srcIP, dstPort, srcPort, ack, seq+payloadLen)
	finalizeChecksums(toClient)
	r.send(toClient, srcIP)
}

func (r *resetSender) close() {
	unix.Close(r.fd)
}
