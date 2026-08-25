package main

import (
	"fmt"
	"log"
	"strings"
	"time"
)

// A Node-family process deleting this many files within this window is
// treated as a bulk-wipe pattern worth flagging (and, if -kill is passed,
// terminating). These are deliberately conservative starting points, NOT
// validated against real workloads — see README: tools like
// rimraf/jest/webpack can legitimately delete many files fast, so this
// needs calibration against your own workflow before -kill is ever
// turned on.
const (
	deleteRateThreshold = 15
	deleteRateWindow    = 3 * time.Second
)

var nodeProcessNames = map[string]bool{
	"node.exe":     true,
	"node64.exe":   true,
	"node":         true, // Linux/macOS binary name has no extension
	"electron.exe": true,
	"electron":     true,
}

func isNodeProcessPath(path string) bool {
	path = strings.ToLower(path)
	idx := strings.LastIndexAny(path, `\/`)
	base := path
	if idx >= 0 {
		base = path[idx+1:]
	}
	return nodeProcessNames[base]
}

// killFunc terminates a process by PID — the one part of this policy that's
// inherently OS-specific (TerminateProcess on Windows, SIGKILL elsewhere),
// so each platform's watcher supplies its own.
type killFunc func(pid uint32) error

// handleNodeDelete is the single policy funnel every platform's file-delete
// watcher (ETW on Windows, auditd on Linux, fs_usage on macOS) feeds into:
// ignore anything that isn't Node-family, log every qualifying delete,
// respect the pause switch, and alert/kill on a bulk-delete pattern. Having
// one shared implementation means the three platforms can't quietly drift
// into different behavior.
func handleNodeDelete(lg *logger, tracker *deleteTracker, ps *pauseSwitch, autoKill bool, kill killFunc, pid uint32, procPath, path string) {
	if pid == 0 || !isNodeProcessPath(procPath) {
		return
	}

	lg.log(logEntry{
		Event:   "file-delete",
		Path:    path,
		Process: procPath,
		PID:     pid,
	})

	if ps.isPaused() {
		// Deliberate bulk-delete in progress — still logged above, just
		// not fed into the rate tracker, so it can't trigger an alert/kill.
		return
	}

	count, justExceeded := tracker.record(pid, time.Now())
	if !justExceeded {
		return
	}

	fmt.Printf("[ALERT] pid %d (%s) deleted %d files within %s — bulk-wipe pattern\n",
		pid, procPath, count, deleteRateWindow)
	lg.log(logEntry{
		Event:   "bulk-delete-alert",
		Process: procPath,
		PID:     pid,
	})

	if !autoKill {
		fmt.Printf("[ALERT] auto-kill disabled (run with -kill to enable) — would have terminated pid %d\n", pid)
		return
	}

	if err := kill(pid); err != nil {
		log.Printf("warning: failed to terminate pid %d: %v", pid, err)
		return
	}
	fmt.Printf("[KILLED] pid %d (%s)\n", pid, procPath)
	tracker.forget(pid)
}
