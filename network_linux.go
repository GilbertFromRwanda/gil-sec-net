package main

import (
	"context"
	"fmt"
	"log"
	"os/exec"

	nfqueue "github.com/florianl/go-nfqueue/v2"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// nfqueueNum must match the --queue-num used in the iptables rule below.
const nfqueueNum = 100

// iptablesRule diverts outbound, non-loopback TCP:80/443 packets to our
// queue. --queue-bypass is the important safety net: if this process isn't
// running (crashed, not started yet), matching packets are ACCEPTed
// instead of stalling — a bug here degrades to "not filtering" rather than
// "no outbound traffic on the box."
func iptablesRuleArgs(action string) []string {
	return []string{
		action, "OUTPUT",
		"!", "-o", "lo",
		"-p", "tcp",
		"-m", "multiport", "--dports", "80,443",
		"-j", "NFQUEUE", "--queue-num", fmt.Sprintf("%d", nfqueueNum), "--queue-bypass",
	}
}

func setupIptablesRule() error {
	cmd := exec.Command("iptables", iptablesRuleArgs("-I")...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables rule setup failed: %w: %s", err, out)
	}
	return nil
}

func teardownIptablesRule() {
	cmd := exec.Command("iptables", iptablesRuleArgs("-D")...)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("warning: failed to remove iptables rule (remove it manually: iptables %v): %v: %s",
			iptablesRuleArgs("-D"), err, out)
	}
}

// runNetworkFilter opens an NFQUEUE handle, inspects the SNI/Host of each
// queued packet (reusing the exact same parsing gil-sec-net uses on
// Windows), and drops+resets any connection matching the blocklist.
// Requires root (raw socket + NFQUEUE) and the `iptables` binary.
func runNetworkFilter(ctx context.Context, bl *blocklist, lg *logger) error {
	if err := setupIptablesRule(); err != nil {
		return err
	}
	fmt.Println("Installed iptables NFQUEUE rule (removed automatically on shutdown)")

	config := nfqueue.Config{
		NfQueue:      nfqueueNum,
		MaxPacketLen: 0xFFFF,
		MaxQueueLen:  0xFF,
		Copymode:     nfqueue.NfQnlCopyPacket,
		AfFamily:     unix.AF_INET,
	}

	nf, err := nfqueue.Open(&config)
	if err != nil {
		teardownIptablesRule()
		return fmt.Errorf("failed to open nfqueue: %w (run as root?)", err)
	}

	if err := nf.SetOption(netlink.NoENOBUFS, true); err != nil {
		log.Printf("warning: failed to set NoENOBUFS: %v", err)
	}

	rs, err := newResetSender()
	if err != nil {
		nf.Close()
		teardownIptablesRule()
		return fmt.Errorf("failed to open raw socket for reset injection: %w", err)
	}

	fn := func(a nfqueue.Attribute) int {
		if a.PacketID == nil {
			return 0
		}
		id := *a.PacketID

		if a.Payload == nil {
			nf.SetVerdict(id, nfqueue.NfAccept)
			return 0
		}
		packet := *a.Payload

		pp, ok := parseIPv4TCP(packet)
		if !ok {
			nf.SetVerdict(id, nfqueue.NfAccept)
			return 0
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
			nf.SetVerdict(id, nfqueue.NfAccept)
			return 0
		}

		nf.SetVerdict(id, nfqueue.NfDrop)

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

		return 0
	}

	errFn := func(e error) int {
		if ctx.Err() != nil {
			return -1 // shutting down
		}
		log.Printf("warning: nfqueue receive error: %v", e)
		return 0
	}

	if err := nf.RegisterWithErrorFunc(ctx, fn, errFn); err != nil {
		rs.close()
		nf.Close()
		teardownIptablesRule()
		return fmt.Errorf("failed to register nfqueue handler: %w", err)
	}

	go func() {
		<-ctx.Done()
		nf.Close()
		rs.close()
		teardownIptablesRule()
	}()

	return nil
}
