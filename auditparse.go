package main

import (
	"strconv"
	"strings"
)

// auditKey tags the rule this program installs via auditctl, so its own
// events can be picked out of a log that may also contain unrelated rules
// (auditd is shared system-wide — we must not assume we're the only rule).
const auditKey = "gilsecnet_delete"

// parseAuditField extracts `key=value` or `key="value"` from a raw
// /var/log/audit/audit.log line (the same line format documented in
// go-libaudit's README and produced by the kernel audit subsystem).
func parseAuditField(line, key string) (string, bool) {
	needle := key + "="
	searchFrom := 0
	idx := -1
	for {
		i := strings.Index(line[searchFrom:], needle)
		if i < 0 {
			break
		}
		pos := searchFrom + i
		// Require a word boundary before the key (start of line or
		// whitespace) so "pid=" doesn't match inside "ppid=".
		if pos == 0 || line[pos-1] == ' ' {
			idx = pos
			break
		}
		searchFrom = pos + 1
	}
	if idx < 0 {
		return "", false
	}
	rest := line[idx+len(key)+1:]
	if len(rest) > 0 && rest[0] == '"' {
		rest = rest[1:]
		end := strings.IndexByte(rest, '"')
		if end < 0 {
			return "", false
		}
		return rest[:end], true
	}
	end := strings.IndexAny(rest, " \n")
	if end < 0 {
		end = len(rest)
	}
	return rest[:end], true
}

// matchDeleteSyscall recognizes a SYSCALL audit record produced by this
// program's own rule (a successful unlink/unlinkat/rmdir/rename/renameat*
// call), and pulls out the PID and executable path.
func matchDeleteSyscall(line string) (pid uint32, exe string, ok bool) {
	if !strings.HasPrefix(line, "type=SYSCALL") {
		return 0, "", false
	}
	if !strings.Contains(line, `key="`+auditKey+`"`) {
		return 0, "", false
	}
	if !strings.Contains(line, "success=yes") {
		return 0, "", false
	}

	pidStr, ok := parseAuditField(line, "pid")
	if !ok {
		return 0, "", false
	}
	p, err := strconv.ParseUint(pidStr, 10, 32)
	if err != nil {
		return 0, "", false
	}

	exe, _ = parseAuditField(line, "exe")
	return uint32(p), exe, true
}
