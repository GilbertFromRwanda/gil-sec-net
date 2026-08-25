// gil-sec-net is the OS-level companion to gil-sec. On macOS:
//   - Network filtering (SNI/Host blocklist matching + RST) is via a pf
//     `divert-to` socket — EXPERIMENTAL, see the top of network_darwin.go.
//   - File-delete detection is a best-effort `fs_usage` parse — real
//     PID-attributed detection needs Apple's EndpointSecurity entitlement,
//     which is a separate approval process, not just more code. See
//     filedelete_darwin.go.
//
// Must run as root.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

const (
	logFileName   = "gil-sec-net.log"
	blocklistName = "blocklist.json"
)

func isRoot() bool {
	u, err := user.Current()
	if err != nil {
		return false
	}
	uid, err := strconv.Atoi(u.Uid)
	return err == nil && uid == 0
}

func main() {
	autoKill := flag.Bool("kill", false, "terminate Node-family processes that cross the bulk-delete threshold (default: log/alert only — see README before enabling)")
	flag.Parse()

	if !isRoot() {
		log.Fatal("gil-sec-net must run as root (divert socket + raw socket + fs_usage all require it)")
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
	fmt.Println("gil-sec-net active — intercepting outbound TCP:80/443 system-wide (EXPERIMENTAL on macOS — see network_darwin.go)")
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
		fmt.Println("File-delete watch active (best-effort — see filedelete_darwin.go)")
	}

	<-sigCh
	fmt.Println("\nShutting down...")
	cancel()
	// Give the pf/fs_usage teardown goroutines a moment to finish before
	// the process exits and takes them down with it.
	time.Sleep(time.Second)
}
