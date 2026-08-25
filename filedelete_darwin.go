package main

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// BEST-EFFORT / UNVERIFIED — true PID-attributed file-delete detection on
// macOS needs Apple's EndpointSecurity framework, which requires a
// `com.apple.developer.endpoint-security.client` entitlement granted by
// Apple (a real approval process, not something buildable from here — and
// EndpointSecurity is cgo/Objective-C-framework territory anyway, which
// can't be cross-compiled from this Windows machine without a macOS SDK).
//
// This instead shells out to `fs_usage` (built into macOS, dtrace-based,
// root-only, no entitlement needed — the same tool Instruments/Activity
// Monitor's sampling uses) and does a defensive best-effort parse of its
// output for delete-related syscalls. fs_usage's exact column layout
// wasn't something this could be verified against on real macOS, so the
// parser deliberately extracts as little as possible (syscall keyword +
// trailing "process.pid" token only, no path) to minimize what can be
// wrong. If this doesn't fire on a real Mac, `fs_usage -w -f filesys` run
// by hand is the place to start — compare its actual line format against
// parseF sUsageLine below.
const fsUsageDeleteKeywords = "unlink rmdir rename"

func startFileDeleteWatch(ctx context.Context, lg *logger, autoKill bool, ps *pauseSwitch) error {
	cmd := exec.Command("fs_usage", "-w", "-f", "filesys")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to open fs_usage stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start fs_usage: %w (run as root?)", err)
	}
	fmt.Println("Started fs_usage for file-delete detection (best-effort — see filedelete_darwin.go)")

	tracker := newDeleteTracker(deleteRateThreshold, deleteRateWindow)

	go func() {
		<-ctx.Done()
		cmd.Process.Kill()
	}()

	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			pid, proc, ok := parseFsUsageLine(scanner.Text())
			if !ok {
				continue
			}
			handleNodeDelete(lg, tracker, ps, autoKill, killProcessUnix, pid, proc, "")
		}
	}()

	return nil
}

// parseFsUsageLine looks for a delete-related syscall keyword anywhere in
// the line, then reads the LAST whitespace-separated token as fs_usage's
// "processname.pid" field. Deliberately doesn't attempt to extract the
// file path — see the package-level comment above for why.
func parseFsUsageLine(line string) (pid uint32, proc string, ok bool) {
	hasDeleteSyscall := false
	for _, kw := range strings.Fields(fsUsageDeleteKeywords) {
		if strings.Contains(line, kw) {
			hasDeleteSyscall = true
			break
		}
	}
	if !hasDeleteSyscall {
		return 0, "", false
	}

	fields := strings.Fields(line)
	if len(fields) == 0 {
		return 0, "", false
	}
	last := fields[len(fields)-1]

	dot := strings.LastIndexByte(last, '.')
	if dot < 0 || dot == len(last)-1 {
		return 0, "", false
	}
	p, err := strconv.ParseUint(last[dot+1:], 10, 32)
	if err != nil {
		return 0, "", false
	}

	return uint32(p), last[:dot], true
}
