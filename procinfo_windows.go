package main

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi                = syscall.NewLazyDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
)

const (
	afINET                = 2
	tcpTableOwnerPidAll   = 5
	errInsufficientBuffer = 122
	tcpRowSize            = 24 // MIB_TCPROW_OWNER_PID
)

// pidForLocalEndpoint finds the PID that owns the outbound TCP connection
// with the given local IPv4 address and port, by walking the same table
// `netstat -ano` reads from.
func pidForLocalEndpoint(localIP [4]byte, localPort uint16) (uint32, bool) {
	var size uint32
	procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, afINET, tcpTableOwnerPidAll, 0)
	if size == 0 {
		return 0, false
	}

	buf := make([]byte, size)
	r1, _, _ := procGetExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
		afINET,
		tcpTableOwnerPidAll,
		0,
	)
	if r1 != 0 {
		return 0, false
	}

	numEntries := binary.LittleEndian.Uint32(buf[0:4])
	for i := uint32(0); i < numEntries; i++ {
		off := 4 + i*tcpRowSize
		if off+tcpRowSize > uint32(len(buf)) {
			break
		}
		row := buf[off : off+tcpRowSize]

		rowAddr := [4]byte{row[4], row[5], row[6], row[7]}
		rowPort := uint16(row[8])<<8 | uint16(row[9])

		if rowAddr == localIP && rowPort == localPort {
			pid := binary.LittleEndian.Uint32(row[20:24])
			return pid, true
		}
	}
	return 0, false
}

// processNameForPID returns the executable path for a PID, or a placeholder
// if the process has already exited or access is denied.
func processNameForPID(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return fmt.Sprintf("pid:%d (unavailable)", pid)
	}
	defer windows.CloseHandle(h)

	buf := make([]uint16, windows.MAX_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return fmt.Sprintf("pid:%d (unavailable)", pid)
	}
	return windows.UTF16ToString(buf[:size])
}
