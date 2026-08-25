package main

import (
	"sync"
	"time"
)

// deleteTracker flags a process deleting an unusual number of files in a
// short window — the signature of a bulk-wipe/ransomware-style operation,
// as opposed to occasional, spread-out deletes from normal tool use.
type deleteTracker struct {
	mu        sync.Mutex
	window    time.Duration
	threshold int
	events    map[uint32][]time.Time
}

func newDeleteTracker(threshold int, window time.Duration) *deleteTracker {
	return &deleteTracker{
		window:    window,
		threshold: threshold,
		events:    make(map[uint32][]time.Time),
	}
}

// record adds a delete event for pid at time `now` and reports how many
// deletes that PID has made within the trailing window, and whether that
// count just crossed the threshold (true only on the event that crosses
// it, not on every one after, so a caller doesn't re-alert per file).
func (t *deleteTracker) record(pid uint32, now time.Time) (count int, justExceeded bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	cutoff := now.Add(-t.window)
	ts := t.events[pid]

	kept := ts[:0]
	for _, e := range ts {
		if e.After(cutoff) {
			kept = append(kept, e)
		}
	}
	kept = append(kept, now)
	t.events[pid] = kept

	count = len(kept)
	justExceeded = count == t.threshold
	return
}

// forget drops tracking state for a PID — call once it's been handled (e.g.
// killed) so a later, unrelated process reusing the same PID doesn't
// inherit a stale count.
func (t *deleteTracker) forget(pid uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.events, pid)
}
