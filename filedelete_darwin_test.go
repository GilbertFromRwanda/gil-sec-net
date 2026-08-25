package main

import "testing"

// These test the parser's own documented contract (keyword match + trailing
// "name.pid" token), NOT that this matches real fs_usage output verbatim —
// see the uncertainty noted in filedelete_darwin.go.
func TestParseFsUsageLine(t *testing.T) {
	cases := []struct {
		line     string
		wantPID  uint32
		wantProc string
		wantOK   bool
	}{
		{
			line:     "13:45:01.123456  unlink            /tmp/foo.txt                0.000012 node.1234",
			wantPID:  1234,
			wantProc: "node",
			wantOK:   true,
		},
		{
			line:     "13:45:01.123456  rmdir             /tmp/somedir                0.000012 electron.5678",
			wantPID:  5678,
			wantProc: "electron",
			wantOK:   true,
		},
		{
			// unrelated syscall — must not match
			line:   "13:45:01.123456  open              /tmp/foo.txt                0.000012 node.1234",
			wantOK: false,
		},
		{
			// trailing token has no PID suffix
			line:   "13:45:01.123456  unlink            /tmp/foo.txt                0.000012 node",
			wantOK: false,
		},
		{line: "", wantOK: false},
	}

	for _, c := range cases {
		pid, proc, ok := parseFsUsageLine(c.line)
		if ok != c.wantOK {
			t.Errorf("parseFsUsageLine(%q) ok = %v, want %v", c.line, ok, c.wantOK)
			continue
		}
		if !ok {
			continue
		}
		if pid != c.wantPID || proc != c.wantProc {
			t.Errorf("parseFsUsageLine(%q) = (%d, %q), want (%d, %q)", c.line, pid, proc, c.wantPID, c.wantProc)
		}
	}
}
