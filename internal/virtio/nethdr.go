package virtio

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

const NetHdrLen = int(unsafe.Sizeof(NetHdr{}))

type NetHdr struct {
	Flags      uint8
	GsoType    uint8
	HdrLen     uint16
	GsoSize    uint16
	CsumStart  uint16
	CsumOffset uint16
	NumBuffers uint16
}

func (v *NetHdr) Decode(b []byte) error {
	if len(b) < NetHdrLen {
		return errors.New("short nethdr buffer length")
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(v)),
		NetHdrLen), b[:NetHdrLen])
	return nil
}

func (v *NetHdr) Encode(b []byte) error {
	if len(b) < NetHdrLen {
		return errors.New("short nethdr buffer length")
	}
	copy(b[:NetHdrLen],
		unsafe.Slice((*byte)(unsafe.Pointer(v)), NetHdrLen))
	return nil
}
