package main

import (
	"testing"
	"time"
)

func TestDeleteTrackerFiresOnceAtThreshold(t *testing.T) {
	tr := newDeleteTracker(5, time.Second)
	now := time.Now()

	var exceededCount int
	for i := 0; i < 10; i++ {
		_, exceeded := tr.record(42, now.Add(time.Duration(i)*10*time.Millisecond))
		if exceeded {
			exceededCount++
		}
	}

	if exceededCount != 1 {
		t.Fatalf("justExceeded fired %d times, want exactly 1 (only at the threshold crossing)", exceededCount)
	}
}

func TestDeleteTrackerPrunesOldEvents(t *testing.T) {
	tr := newDeleteTracker(3, 100*time.Millisecond)
	now := time.Now()

	tr.record(1, now)
	tr.record(1, now.Add(10*time.Millisecond))

	// Well outside the window — the two events above should have aged out,
	// so this shouldn't immediately trip the threshold just because it's
	// the 3rd call overall.
	count, exceeded := tr.record(1, now.Add(500*time.Millisecond))
	if count != 1 {
		t.Fatalf("count = %d, want 1 (old events should have been pruned)", count)
	}
	if exceeded {
		t.Fatalf("justExceeded = true, want false after pruning")
	}
}

func TestDeleteTrackerPerPIDIsolation(t *testing.T) {
	tr := newDeleteTracker(2, time.Second)
	now := time.Now()

	tr.record(1, now)
	count, exceeded := tr.record(2, now)
	if count != 1 || exceeded {
		t.Fatalf("pid 2's count was affected by pid 1's events: count=%d exceeded=%v", count, exceeded)
	}
}

func TestDeleteTrackerForget(t *testing.T) {
	tr := newDeleteTracker(2, time.Second)
	now := time.Now()

	tr.record(1, now)
	tr.forget(1)

	count, exceeded := tr.record(1, now.Add(time.Millisecond))
	if count != 1 || exceeded {
		t.Fatalf("after forget(), count=%d exceeded=%v, want count=1 exceeded=false", count, exceeded)
	}
}

func TestIsNodeProcessPath(t *testing.T) {
	cases := map[string]bool{
		`C:\Program Files\nodejs\node.exe`:                 true,
		`C:\Program Files\nodejs\NODE.EXE`:                 true,
		`C:\Users\dev\AppData\Local\Programs\electron.exe`: true,
		`C:\Windows\System32\notepad.exe`:                  false,
		`C:\Program Files\nodejs\node.exe.manifest`:        false,
		"pid:1234 (unavailable)":                           false,
		"":                                                 false,
	}
	for path, want := range cases {
		if got := isNodeProcessPath(path); got != want {
			t.Errorf("isNodeProcessPath(%q) = %v, want %v", path, got, want)
		}
	}
}
