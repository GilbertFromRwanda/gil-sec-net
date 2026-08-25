package main

import (
	"context"
	"fmt"

	"github.com/0xrawsec/golang-etw/etw"
	"golang.org/x/sys/windows"
)

const (
	// NameDelete fires when a name is removed from the NTFS name cache —
	// the reliable signal for an actual file delete. DeletePath is the
	// newer template variant that additionally carries a resolved path.
	// (SetDelete/18 also exists but only carries an opaque FileKey, not a
	// resolvable path, so it's not useful here without extra bookkeeping.)
	etwEventNameDelete = 11
	etwEventDeletePath = 26
)

// startFileDeleteWatch consumes Microsoft-Windows-Kernel-File delete events
// system-wide via ETW (the same OS facility Process Monitor is built on —
// no custom driver, and unlike WinDivert it needs no DLL/driver files of
// its own). Every delete event carries the emitting process's PID in the
// common ETW event header, so — unlike a ReadDirectoryChangesW watcher —
// this can actually attribute each delete to a process.
func startFileDeleteWatch(ctx context.Context, lg *logger, autoKill bool, ps *pauseSwitch) error {
	session := etw.NewRealTimeSession("gil-sec-net-filewatch")

	prov := etw.MustParseProvider("Microsoft-Windows-Kernel-File")
	prov.Filter = []uint16{etwEventNameDelete, etwEventDeletePath}

	if err := session.EnableProvider(prov); err != nil {
		session.Stop()
		return fmt.Errorf("failed to enable Kernel-File ETW provider: %w (run as Administrator?)", err)
	}

	consumer := etw.NewRealTimeConsumer(ctx)
	consumer.FromSessions(session)

	tracker := newDeleteTracker(deleteRateThreshold, deleteRateWindow)

	go func() {
		<-ctx.Done()
		consumer.Stop()
		session.Stop()
	}()

	go func() {
		for event := range consumer.Events {
			handleETWEvent(event, lg, tracker, autoKill, ps)
		}
	}()

	if err := consumer.Start(); err != nil {
		return fmt.Errorf("failed to start ETW consumer: %w", err)
	}
	return nil
}

func handleETWEvent(event *etw.Event, lg *logger, tracker *deleteTracker, autoKill bool, ps *pauseSwitch) {
	pid := event.System.Execution.ProcessID
	if pid == 0 {
		return
	}

	procPath := processNameForPID(pid)

	path, ok := event.GetPropertyString("FileName")
	if !ok || path == "" {
		path, _ = event.GetPropertyString("FilePath")
	}

	handleNodeDelete(lg, tracker, ps, autoKill, killProcessWindows, pid, procPath, path)
}

func killProcessWindows(pid uint32) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return windows.TerminateProcess(h, 1)
}
