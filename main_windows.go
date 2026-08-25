// gil-sec-net is the OS-level companion to gil-sec: it intercepts outbound
// TCP traffic system-wide (every process, not just ones that require() the
// Node monitor) using WinDivert, inspects the TLS SNI / HTTP Host header of
// each new connection, and resets any connection headed to a blocklisted
// domain — regardless of which process or language made it.
//
// Must run elevated (WinDivert loads a kernel driver). WinDivert.dll and
// WinDivert64.sys must sit next to this executable.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
)

const (
	filter        = "outbound && !loopback && ip && tcp && (tcp.DstPort == 443 || tcp.DstPort == 80) && tcp.PayloadLength > 0"
	priority      = 750
	logFileName   = "gil-sec-net.log"
	blocklistName = "blocklist.json"
)

func main() {
	autoKill := flag.Bool("kill", false, "terminate Node-family processes that cross the bulk-delete threshold (default: log/alert only — see README before enabling)")
	flag.Parse()

	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("failed to resolve executable path: %v", err)
	}
	dir := filepath.Dir(exePath)

	wd, err := loadWinDivert(dir)
	if err != nil {
		log.Fatalf("%v", err)
	}

	bl, err := loadBlocklist(filepath.Join(dir, blocklistName))
	if err != nil {
		log.Fatalf("failed to load %s: %v", blocklistName, err)
	}
	fmt.Printf("Loaded %d blocklisted domain(s) from %s\n", len(bl.domains), blocklistName)

	lg, err := newLogger(filepath.Join(dir, logFileName))
	if err != nil {
		log.Fatalf("failed to open log file: %v", err)
	}
	defer lg.close()

	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)

	handle, err := wd.open(filter, windivertLayerNetwork, priority, 0)
	if err != nil {
		log.Fatalf("WinDivertOpen failed: %v (run as Administrator?)", err)
	}
	defer wd.close(handle)

	go func() {
		<-sigCh
		fmt.Println("\nShutting down...")
		cancel()
		wd.close(handle) // unblocks the pending WinDivertRecv below
	}()

	if *autoKill {
		fmt.Println("Auto-kill ENABLED — Node-family processes crossing the bulk-delete threshold will be terminated")
	} else {
		fmt.Println("Auto-kill disabled (default) — bulk-delete patterns are logged/alerted only. Pass -kill to enable termination.")
	}

	ps := newPauseSwitch(dir)
	go ps.watch(ctx, lg)
	fmt.Printf("To pause bulk-delete detection for an intentional cleanup, create %s (delete it to resume)\n", filepath.Join(dir, pauseFileName))

	if err := startFileDeleteWatch(ctx, lg, *autoKill, ps); err != nil {
		log.Printf("warning: file-delete watch not started: %v", err)
	} else {
		fmt.Println("File-delete watch active — Node-family processes, system-wide")
	}

	fmt.Println("gil-sec-net active — intercepting outbound TCP:80/443 system-wide")
	fmt.Printf("Log file: %s\n", filepath.Join(dir, logFileName))

	packetBuf := make([]byte, maxPacketSize)

	for {
		var addr windivertAddress
		n, err := wd.recv(handle, packetBuf, &addr)
		if err != nil {
			if ctx.Err() != nil {
				return // shutting down — WinDivertClose interrupted this recv on purpose
			}
			// A transient recv error shouldn't kill the whole monitor.
			log.Printf("warning: recv failed: %v", err)
			continue
		}
		packet := packetBuf[:n]

		pp, ok := parseIPv4TCP(packet)
		if !ok {
			wd.send(handle, packet, &addr)
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
			// Not a match (or nothing recognizable) — pass through unchanged.
			if err := wd.send(handle, packet, &addr); err != nil {
				log.Printf("warning: failed to reinject packet: %v", err)
			}
			continue
		}

		// Blocked: don't reinject the request itself, and tear down the
		// connection at both ends so the caller sees an immediate failure
		// (ECONNRESET) instead of hanging until a retransmit timeout.
		var srcIP, dstIP [4]byte
		copy(srcIP[:], pp.srcIP.To4())
		copy(dstIP[:], pp.dstIP.To4())

		pid, havePID := pidForLocalEndpoint(srcIP, pp.srcPort)
		procName := ""
		if havePID {
			procName = processNameForPID(pid)
		}

		fmt.Printf("[BLOCKED] %s -> %s (%s:%d) matched %q  process=%s\n",
			hostname, matched, pp.dstIP, pp.dstPort, matched, procName)

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

		// (1) RST toward the remote server, same direction as the original packet.
		toServer := buildResetPacket(srcIP, dstIP, pp.srcPort, pp.dstPort, pp.seq, pp.ack)
		wd.calcChecksums(toServer, &addr)
		if err := wd.send(handle, toServer, &addr); err != nil {
			log.Printf("warning: failed to send reset toward server: %v", err)
		}

		// (2) RST toward the local client, injected as inbound so the local
		// TCP stack tears the socket down immediately.
		payloadLen := uint32(len(pp.payload))
		toClient := buildResetPacket(dstIP, srcIP, pp.dstPort, pp.srcPort, pp.ack, pp.seq+payloadLen)
		clientAddr := addr
		clientAddr.toggleOutbound()
		wd.calcChecksums(toClient, &clientAddr)
		if err := wd.send(handle, toClient, &clientAddr); err != nil {
			log.Printf("warning: failed to send reset toward client: %v", err)
		}
	}
}
