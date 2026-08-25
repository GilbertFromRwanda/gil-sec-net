// gil-sec-net is the OS-level companion to gil-sec: it intercepts outbound
// TCP traffic system-wide using NFQUEUE, inspects the TLS SNI / HTTP Host
// header of each new connection, and resets any connection headed to a
// blocklisted domain — regardless of which process or language made it.
// It also watches for Node-family processes deleting an unusual number of
// files in a short window (via auditd) and can optionally kill them.
//
// Must run as root. Requires the `iptables` and `auditctl` binaries, and a
// running auditd (for the file-delete watch — the network filter works
// without it).
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

const (
	logFileName   = "gil-sec-net.log"
	blocklistName = "blocklist.json"
)

func main() {
	autoKill := flag.Bool("kill", false, "terminate Node-family processes that cross the bulk-delete threshold (default: log/alert only — see README before enabling)")
	flag.Parse()

	if os.Geteuid() != 0 {
		log.Fatal("gil-sec-net must run as root (NFQUEUE + raw sockets + auditd all require it)")
	}

	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("failed to resolve executable path: %v", err)
	}
	dir := filepath.Dir(exePath)

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
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	if err := runNetworkFilter(ctx, bl, lg); err != nil {
		log.Fatalf("%v", err)
	}
	fmt.Println("gil-sec-net active — intercepting outbound TCP:80/443 system-wide")
	fmt.Printf("Log file: %s\n", filepath.Join(dir, logFileName))

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

	<-sigCh
	fmt.Println("\nShutting down...")
	cancel()
	// Give the network/audit teardown goroutines (each just a couple of
	// quick exec.Command calls) time to finish removing the iptables/
	// auditctl rules before the process exits — those goroutines are
	// killed outright the instant main() returns.
	time.Sleep(time.Second)
}
