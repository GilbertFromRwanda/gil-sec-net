package main

import (
	"fmt"
	"path/filepath"
	"syscall"
	"unsafe"
)

// Matches WINDIVERT_LAYER in windivert.h.
const windivertLayerNetwork = 0

// windivertAddress mirrors WINDIVERT_ADDRESS from windivert.h:
//
//	INT64  Timestamp;
//	UINT32 Layer:8, Event:8, Sniffed:1, Outbound:1, Loopback:1, Impostor:1,
//	       IPv6:1, IPChecksum:1, TCPChecksum:1, UDPChecksum:1, Reserved1:8;
//	UINT32 Reserved2;
//	union { WINDIVERT_DATA_NETWORK Network; ...; UINT8 Reserved3[64]; };
//
// The 32-bit bitfield packs LSB-first (MSVC x64), so Outbound is bit 17.
// We never need the union's contents — a captured address is only ever
// passed back into WinDivertSend unmodified (aside from toggling Outbound).
type windivertAddress struct {
	Timestamp int64
	flags     uint32
	reserved2 uint32
	union     [64]byte
}

const outboundBit = 1 << 17

func (a *windivertAddress) outbound() bool {
	return a.flags&outboundBit != 0
}

func (a *windivertAddress) toggleOutbound() {
	a.flags ^= outboundBit
}

type winDivert struct {
	dll                     *syscall.LazyDLL
	procOpen                *syscall.LazyProc
	procRecv                *syscall.LazyProc
	procSend                *syscall.LazyProc
	procClose               *syscall.LazyProc
	procHelperCalcChecksums *syscall.LazyProc
}

func loadWinDivert(dllDir string) (*winDivert, error) {
	dllPath := filepath.Join(dllDir, "WinDivert.dll")
	dll := syscall.NewLazyDLL(dllPath)
	if err := dll.Load(); err != nil {
		return nil, fmt.Errorf("failed to load %s: %w (is WinDivert64.sys next to it?)", dllPath, err)
	}

	return &winDivert{
		dll:                     dll,
		procOpen:                dll.NewProc("WinDivertOpen"),
		procRecv:                dll.NewProc("WinDivertRecv"),
		procSend:                dll.NewProc("WinDivertSend"),
		procClose:               dll.NewProc("WinDivertClose"),
		procHelperCalcChecksums: dll.NewProc("WinDivertHelperCalcChecksums"),
	}, nil
}

func (w *winDivert) open(filter string, layer uint8, priority int16, flags uint64) (syscall.Handle, error) {
	cFilter, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return 0, err
	}

	r1, _, e1 := w.procOpen.Call(
		uintptr(unsafe.Pointer(cFilter)),
		uintptr(layer),
		uintptr(uint16(priority)),
		uintptr(flags),
	)
	h := syscall.Handle(r1)
	if h == syscall.InvalidHandle {
		return h, e1
	}
	return h, nil
}

func (w *winDivert) recv(handle syscall.Handle, packet []byte, addr *windivertAddress) (uint32, error) {
	var recvLen uint32
	r1, _, e1 := w.procRecv.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(uint32(len(packet))),
		uintptr(unsafe.Pointer(&recvLen)),
		uintptr(unsafe.Pointer(addr)),
	)
	if r1 == 0 {
		return 0, e1
	}
	return recvLen, nil
}

func (w *winDivert) send(handle syscall.Handle, packet []byte, addr *windivertAddress) error {
	r1, _, e1 := w.procSend.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(uint32(len(packet))),
		0, // pSendLen — we don't need the actual bytes-sent count
		uintptr(unsafe.Pointer(addr)),
	)
	if r1 == 0 {
		return e1
	}
	return nil
}

func (w *winDivert) close(handle syscall.Handle) {
	w.procClose.Call(uintptr(handle))
}

func (w *winDivert) calcChecksums(packet []byte, addr *windivertAddress) {
	w.procHelperCalcChecksums.Call(
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(uint32(len(packet))),
		uintptr(unsafe.Pointer(addr)),
		0,
	)
}
