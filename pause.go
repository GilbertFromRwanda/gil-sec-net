package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

const (
	pauseFileName     = "gil-sec-net.pause"
	pausePollInterval = 250 * time.Millisecond
)

// pauseSwitch is a deliberate, manual "I'm about to do a big delete on
// purpose" override for the file-delete watch, controlled by the presence
// of a file next to the executable. Deletes are still logged while
// paused — they're just not fed into the bulk-delete rate tracker, so they
// can't trigger an alert or -kill.
type pauseSwitch struct {
	path   string
	active atomic.Bool
}

func newPauseSwitch(dir string) *pauseSwitch {
	return &pauseSwitch{path: filepath.Join(dir, pauseFileName)}
}

func (p *pauseSwitch) isPaused() bool {
	return p.active.Load()
}

// checkOnce polls for the pause file's presence and updates active,
// printing/logging on each transition so the change is obvious. Split out
// from watch() so it's callable directly.
func (p *pauseSwitch) checkOnce(lg *logger) {
	_, err := os.Stat(p.path)
	now := err == nil
	if now == p.active.Load() {
		return
	}
	p.active.Store(now)

	if now {
		fmt.Printf("[PAUSED] %s present — bulk-delete detection suspended (deletes still logged)\n", pauseFileName)
		lg.log(logEntry{Event: "pause-enabled"})
	} else {
		fmt.Println("[RESUMED] bulk-delete detection active again")
		lg.log(logEntry{Event: "pause-disabled"})
	}
}

// watch polls for the pause file until ctx is canceled.
func (p *pauseSwitch) watch(ctx context.Context, lg *logger) {
	ticker := time.NewTicker(pausePollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.checkOnce(lg)
		}
	}
}
