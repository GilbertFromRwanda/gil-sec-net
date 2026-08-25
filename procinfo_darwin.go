package main

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// processNameForPID shells out to `ps` rather than any lower-level API —
// on macOS that's the safer bet given no way to verify a raw syscall
// approach here. `-o comm=` gives just the command name (no args), which
// is enough for isNodeProcessPath (it already matches on bare "node" as
// well as "node.exe", specifically for this case).
func processNameForPID(pid uint32) string {
	out, err := exec.Command("ps", "-o", "comm=", "-p", strconv.FormatUint(uint64(pid), 10)).Output()
	name := strings.TrimSpace(string(out))
	if err != nil || name == "" {
		return fmt.Sprintf("pid:%d (unavailable)", pid)
	}
	return name
}

// pidForLocalEndpoint shells out to `lsof` to find the PID owning an
// outbound TCP connection from the given local port. Best-effort: filters
// by port via lsof's own -iTCP:<port> selector, then double-checks the
// local side of the NAME field actually ends in that port before trusting
// the match (lsof's port filter matches either side of a connection).
func pidForLocalEndpoint(localIP [4]byte, localPort uint16) (uint32, bool) {
	out, err := exec.Command("lsof", "-nP", "-iTCP:"+strconv.Itoa(int(localPort)), "-sTCP:ESTABLISHED").Output()
	if err != nil {
		return 0, false
	}

	portSuffix := fmt.Sprintf(":%d->", localPort)
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}
		name := fields[8] // NAME column, e.g. "10.0.0.5:54321->93.184.216.34:443"
		if !strings.Contains(name, portSuffix) {
			continue
		}
		pid, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil {
			continue
		}
		return uint32(pid), true
	}
	return 0, false
}
