package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPauseSwitchTogglesOnFilePresence(t *testing.T) {
	dir := t.TempDir()
	ps := newPauseSwitch(dir)
	lg, err := newLogger(filepath.Join(dir, "test.log"))
	if err != nil {
		t.Fatalf("newLogger: %v", err)
	}
	defer lg.close()

	if ps.isPaused() {
		t.Fatalf("isPaused() = true before the pause file was ever created")
	}

	pauseFile := filepath.Join(dir, pauseFileName)
	if err := os.WriteFile(pauseFile, nil, 0644); err != nil {
		t.Fatalf("failed to create pause file: %v", err)
	}
	ps.checkOnce(lg)
	if !ps.isPaused() {
		t.Fatalf("isPaused() = false after creating %s, want true", pauseFileName)
	}

	if err := os.Remove(pauseFile); err != nil {
		t.Fatalf("failed to remove pause file: %v", err)
	}
	ps.checkOnce(lg)
	if ps.isPaused() {
		t.Fatalf("isPaused() = true after removing %s, want false", pauseFileName)
	}
}

func TestPauseSwitchDefaultUnpaused(t *testing.T) {
	dir := t.TempDir() // never contains the pause file
	ps := newPauseSwitch(dir)
	if ps.isPaused() {
		t.Fatalf("a freshly created pauseSwitch reported paused with no file ever created")
	}
}
