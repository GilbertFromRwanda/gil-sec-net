package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"
)

const auditLogPath = "/var/log/audit/audit.log"

var deleteSyscalls = []string{"unlink", "unlinkat", "rmdir", "rename", "renameat", "renameat2"}

func auditRuleArgs(add bool) []string {
	flag := "-a"
	if !add {
		flag = "-d"
	}
	args := []string{flag, "always,exit", "-F", "arch=b64", "-k", auditKey}
	for _, s := range deleteSyscalls {
		args = append(args, "-S", s)
	}
	return args
}

func setupAuditRule() error {
	out, err := exec.Command("auditctl", auditRuleArgs(true)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("auditctl rule setup failed: %w: %s (is auditd installed and running?)", err, out)
	}
	return nil
}

func teardownAuditRule() {
	if out, err := exec.Command("auditctl", auditRuleArgs(false)...).CombinedOutput(); err != nil {
		log.Printf("warning: failed to remove audit rule (remove it manually: auditctl %v): %v: %s",
			auditRuleArgs(false), err, out)
	}
}

// startFileDeleteWatch installs an auditd rule watching every
// unlink/unlinkat/rmdir/rename* syscall system-wide, then tails
// /var/log/audit/audit.log for SYSCALL records carrying our rule's key.
// Requires root, the `auditctl` binary, and a running auditd writing to
// the default log path.
func startFileDeleteWatch(ctx context.Context, lg *logger, autoKill bool, ps *pauseSwitch) error {
	if err := setupAuditRule(); err != nil {
		return err
	}
	fmt.Println("Installed auditd rule for file deletion (removed automatically on shutdown)")

	tracker := newDeleteTracker(deleteRateThreshold, deleteRateWindow)

	go func() {
		<-ctx.Done()
		teardownAuditRule()
	}()

	go tailAuditLog(ctx, lg, tracker, autoKill, ps)

	return nil
}

// tailAuditLog polls audit.log for new lines like `tail -f`, reopening the
// file if it shrinks (log rotation).
func tailAuditLog(ctx context.Context, lg *logger, tracker *deleteTracker, autoKill bool, ps *pauseSwitch) {
	var f *os.File
	var reader *bufio.Reader
	var lastSize int64

	openAtEnd := func() {
		if f != nil {
			f.Close()
		}
		var err error
		f, err = os.Open(auditLogPath)
		if err != nil {
			log.Printf("warning: cannot open %s: %v", auditLogPath, err)
			f = nil
			reader = nil
			return
		}
		info, _ := f.Stat()
		if info != nil {
			lastSize = info.Size()
		}
		f.Seek(0, os.SEEK_END)
		reader = bufio.NewReader(f)
	}
	openAtEnd()

	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			if f != nil {
				f.Close()
			}
			return
		case <-ticker.C:
			if f == nil {
				openAtEnd()
				continue
			}
			info, err := f.Stat()
			if err != nil {
				openAtEnd()
				continue
			}
			if info.Size() < lastSize {
				// File was truncated/rotated out from under us.
				openAtEnd()
				continue
			}
			lastSize = info.Size()

			for {
				line, err := reader.ReadString('\n')
				if line != "" {
					pid, exe, ok := matchDeleteSyscall(line)
					if ok {
						handleNodeDelete(lg, tracker, ps, autoKill, killProcessUnix, pid, exe, "")
					}
				}
				if err != nil {
					break // caught up — wait for the next tick
				}
			}
		}
	}
}
