package main

import "testing"

func TestParseAuditField(t *testing.T) {
	line := `type=SYSCALL msg=audit(1481077334.304:547): arch=c000003e syscall=87 success=yes exit=0 a0=7f6 items=1 ppid=1000 pid=12345 auid=1000 uid=0 gid=0 comm="node" exe="/usr/bin/node" key="gilsecnet_delete"`

	cases := map[string]string{
		"pid":  "12345",
		"exe":  "/usr/bin/node",
		"comm": "node",
		"key":  "gilsecnet_delete",
	}
	for key, want := range cases {
		got, ok := parseAuditField(line, key)
		if !ok || got != want {
			t.Errorf("parseAuditField(%q) = %q, %v — want %q, true", key, got, ok, want)
		}
	}

	if _, ok := parseAuditField(line, "nonexistent"); ok {
		t.Errorf("parseAuditField found a field that isn't in the line")
	}
}

func TestMatchDeleteSyscall(t *testing.T) {
	nodeDelete := `type=SYSCALL msg=audit(1481077334.304:547): arch=c000003e syscall=87 success=yes exit=0 items=1 pid=12345 uid=0 comm="node" exe="/usr/bin/node" key="gilsecnet_delete"`

	pid, exe, ok := matchDeleteSyscall(nodeDelete)
	if !ok {
		t.Fatalf("matchDeleteSyscall failed to match a well-formed delete record")
	}
	if pid != 12345 {
		t.Errorf("pid = %d, want 12345", pid)
	}
	if exe != "/usr/bin/node" {
		t.Errorf("exe = %q, want /usr/bin/node", exe)
	}
}

func TestMatchDeleteSyscallRejectsNonMatches(t *testing.T) {
	cases := []string{
		// wrong record type
		`type=PATH msg=audit(1481077334.304:547): item=0 name="/tmp/foo" key="gilsecnet_delete"`,
		// unrelated audit rule (different key) — must not be picked up as ours
		`type=SYSCALL msg=audit(1481077334.304:547): success=yes pid=999 exe="/usr/bin/bash" key="some_other_rule"`,
		// failed syscall — nothing was actually deleted
		`type=SYSCALL msg=audit(1481077334.304:547): success=no pid=12345 exe="/usr/bin/node" key="gilsecnet_delete"`,
		// our key, but no pid field at all
		`type=SYSCALL msg=audit(1481077334.304:547): success=yes exe="/usr/bin/node" key="gilsecnet_delete"`,
		"",
	}
	for _, line := range cases {
		if _, _, ok := matchDeleteSyscall(line); ok {
			t.Errorf("matchDeleteSyscall incorrectly matched: %q", line)
		}
	}
}
