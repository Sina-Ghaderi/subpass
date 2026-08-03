package nethdr

import (
	"errors"
	"unsafe"
)

const (
	VirtioNetHdrNeedsCsum = 0x1
	VirtioNetHdrDataValid = 0x2
	VirtioNetHdrRscInfo   = 0x4
)

const (
	VirtioNetHdrGsoNone  = 0x0
	VirtioNetHdrGsoTcpV4 = 0x1
	VirtioNetHdrGsoUdp   = 0x3
	VirtioNetHdrGsoTcpV6 = 0x4
	VirtioNetHdrGsoUdpL4 = 0x5
	VirtioNetHdrGsoEcn   = 0x80
)

const VirtioNetHdrLen = int(unsafe.Sizeof(VirtioNetHdr{}))

type VirtioNetHdr struct {
	Flags      uint8
	GsoType    uint8
	HdrLen     uint16
	GsoSize    uint16
	CsumStart  uint16
	CsumOffset uint16
}

func (v *VirtioNetHdr) Decode(b []byte) error {
	if len(b) < VirtioNetHdrLen {
		return errors.New("short nethdr buffer length")
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(v)),
		VirtioNetHdrLen), b[:VirtioNetHdrLen])
	return nil
}

func (v *VirtioNetHdr) Encode(b []byte) error {
	if len(b) < VirtioNetHdrLen {
		return errors.New("short nethdr buffer length")
	}
	copy(b[:VirtioNetHdrLen],
		unsafe.Slice((*byte)(unsafe.Pointer(v)), VirtioNetHdrLen))
	return nil
}
