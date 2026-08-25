//go:build linux || darwin

package main

import "syscall"

func killProcessUnix(pid uint32) error {
	return syscall.Kill(int(pid), syscall.SIGKILL)
}
