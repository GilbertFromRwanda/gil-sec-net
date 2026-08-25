package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// processNameForPID resolves a PID to its executable path via the /proc/pid/exe
// symlink — same idea as the Windows QueryFullProcessImageName lookup.
func processNameForPID(pid uint32) string {
	path, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return fmt.Sprintf("pid:%d (unavailable)", pid)
	}
	return path
}

// pidForLocalEndpoint finds the PID owning the outbound TCP connection with
// the given local IPv4 address and port, using the same two-step technique
// `ss`/`lsof` use under the hood: match the endpoint in /proc/net/tcp to
// find its socket inode, then scan every process's /proc/pid/fd for a
// symlink to that inode.
func pidForLocalEndpoint(localIP [4]byte, localPort uint16) (uint32, bool) {
	inode, ok := findSocketInode(localIP, localPort)
	if !ok {
		return 0, false
	}
	return findPIDForInode(inode)
}

// findSocketInode parses /proc/net/tcp. Each line's local_address field is
// "IP:PORT" in hex, with the IP's bytes stored in the CPU's native byte
// order (little-endian on x86/x86_64) rather than network order — a
// well-known quirk of this file.
func findSocketInode(localIP [4]byte, localPort uint16) (string, bool) {
	f, err := os.Open("/proc/net/tcp")
	if err != nil {
		return "", false
	}
	defer f.Close()

	target := fmt.Sprintf("%02X%02X%02X%02X:%04X", localIP[3], localIP[2], localIP[1], localIP[0], localPort)

	scanner := bufio.NewScanner(f)
	scanner.Scan() // header line
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}
		if fields[1] == target {
			return fields[9], true // inode column
		}
	}
	return "", false
}

// findPIDForInode scans /proc/*/fd/* for a "socket:[<inode>]" symlink.
func findPIDForInode(inode string) (uint32, bool) {
	target := "socket:[" + inode + "]"

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, false
	}

	for _, e := range entries {
		pid, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue // not a PID directory
		}

		fdDir := fmt.Sprintf("/proc/%d/fd", pid)
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue // process exited, or no permission
		}
		for _, fd := range fds {
			link, err := os.Readlink(fdDir + "/" + fd.Name())
			if err == nil && link == target {
				return uint32(pid), true
			}
		}
	}
	return 0, false
}
