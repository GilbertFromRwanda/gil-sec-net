package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"

	"golang.org/x/sys/unix"
)

// EXPERIMENTAL — unlike the Windows (WinDivert) and Linux (NFQUEUE)
// backends, this one has no verified reference implementation behind it
// and has never run on real macOS; there was no solid Go/macOS divert
// socket example to ground it in (see the conversation this was built in).
// If it doesn't work, start by checking: (1) the `divert-to` pf syntax
// below against `man pf.conf` on the actual OS version, (2) whether the
// divert port needs to be bound to 127.0.0.1 specifically vs INADDR_ANY,
// (3) whether IPPROTO_DIVERT is still 254 on the target Darwin version.

// IPPROTO_DIVERT isn't exposed by golang.org/x/sys/unix on darwin (divert
// sockets are BSD-niche); 254 is the long-standing value across the BSD
// family (FreeBSD's sys/netinet/in.h, inherited by macOS).
const ipprotoDivert = 254

const (
	divertPort   = 7777
	pfAnchorName = "gil-sec-net"
)

func pfAnchorRules() string {
	return fmt.Sprintf(
		"pass out quick on ! lo0 proto tcp to port { 80 443 } divert-to 127.0.0.1 port %d\n",
		divertPort,
	)
}

func setupPfRule() error {
	// Make sure pf is enabled — ignore the error if it already is.
	exec.Command("pfctl", "-e").Run()

	f, err := os.CreateTemp("", "gil-sec-net-pf-*.conf")
	if err != nil {
		return fmt.Errorf("failed to write temp pf anchor file: %w", err)
	}
	defer os.Remove(f.Name())

	if _, err := f.WriteString(pfAnchorRules()); err != nil {
		f.Close()
		return err
	}
	f.Close()

	out, err := exec.Command("pfctl", "-a", pfAnchorName, "-f", f.Name()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("pfctl anchor load failed: %w: %s", err, out)
	}
	return nil
}

// teardownPfRule flushes only this program's own anchor — it deliberately
// never runs `pfctl -d` (global disable), since pf may have been serving
// other rules before this program started, or may be relied on by
// something else on the system.
func teardownPfRule() {
	if out, err := exec.Command("pfctl", "-a", pfAnchorName, "-F", "all").CombinedOutput(); err != nil {
		log.Printf("warning: failed to flush pf anchor %q (remove it manually: pfctl -a %s -F all): %v: %s",
			pfAnchorName, pfAnchorName, err, out)
	}
}

// runNetworkFilter opens a divert socket bound to the port the pf anchor
// above redirects to, inspects the SNI/Host of each diverted packet
// (reusing the same parsing used on Windows/Linux), and either reinjects
// it unchanged (echoing back the exact `from` address recvfrom gave us —
// deliberately never hand-constructed, see note above) or drops it by
// simply not resending, plus injects RSTs via a separate raw socket.
func runNetworkFilter(ctx context.Context, bl *blocklist, lg *logger) error {
	if err := setupPfRule(); err != nil {
		return err
	}
	fmt.Println("Installed pf divert rule (flushed automatically on shutdown)")

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, ipprotoDivert)
	if err != nil {
		teardownPfRule()
		return fmt.Errorf("failed to open divert socket: %w (run as root?)", err)
	}

	if err := unix.Bind(fd, &unix.SockaddrInet4{Port: divertPort, Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		unix.Close(fd)
		teardownPfRule()
		return fmt.Errorf("failed to bind divert socket to port %d: %w", divertPort, err)
	}

	rs, err := newResetSender()
	if err != nil {
		unix.Close(fd)
		teardownPfRule()
		return fmt.Errorf("failed to open raw socket for reset injection: %w", err)
	}

	go func() {
		<-ctx.Done()
		unix.Close(fd)
		rs.close()
		teardownPfRule()
	}()

	go divertLoop(fd, bl, lg, rs)

	return nil
}

func divertLoop(fd int, bl *blocklist, lg *logger, rs *resetSender) {
	buf := make([]byte, maxPacketSize)

	for {
		n, from, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			// Socket closed on shutdown, or a transient error.
			return
		}
		packet := buf[:n]

		pp, ok := parseIPv4TCP(packet)
		if !ok {
			unix.Sendto(fd, packet, 0, from)
			continue
		}

		var hostname string
		switch pp.dstPort {
		case 443:
			hostname = extractSNI(pp.payload)
		case 80:
			hostname = extractHost(pp.payload)
		}

		matched := ""
		if hostname != "" {
			matched = bl.match(hostname)
		}

		if matched == "" {
			unix.Sendto(fd, packet, 0, from)
			continue
		}

		// Blocked — don't reinject; the packet is simply dropped.
		var srcIP, dstIP [4]byte
		copy(srcIP[:], pp.srcIP.To4())
		copy(dstIP[:], pp.dstIP.To4())

		pid, havePID := pidForLocalEndpoint(srcIP, pp.srcPort)
		procName := ""
		if havePID {
			procName = processNameForPID(pid)
		}

		fmt.Printf("[BLOCKED] %s -> %s (%s:%d) process=%s\n", hostname, matched, pp.dstIP, pp.dstPort, procName)
		lg.log(logEntry{
			Event:    "blocked",
			Hostname: hostname,
			Domain:   matched,
			SrcIP:    pp.srcIP.String(),
			SrcPort:  pp.srcPort,
			DstIP:    pp.dstIP.String(),
			DstPort:  pp.dstPort,
			Process:  procName,
			PID:      pid,
		})

		rs.sendResets(srcIP, dstIP, pp.srcPort, pp.dstPort, pp.seq, pp.ack, uint32(len(pp.payload)))
	}
}
