package tcpip

import (
	"encoding/binary"
	"errors"
)

const (
	TCPFlagFIN = 1 << iota
	TCPFlagSYN
	TCPFlagRST
	TCPFlagPSH
	TCPFlagACK
	TCPFlagURG
)

const MinTCPHdrLen = 0x14
const MaxTCPHdrLen = 0x3c

func be16(b []byte) uint16        { return binary.BigEndian.Uint16(b) }
func be32(b []byte) uint32        { return binary.BigEndian.Uint32(b) }
func setbe16(b []byte, pv uint16) { binary.BigEndian.PutUint16(b, pv) }
func setbe32(b []byte, pv uint32) { binary.BigEndian.PutUint32(b, pv) }

type TCPHeader []byte

type TCPHeaderInfo struct {
	seqNum        uint32
	ackNum        uint32
	srcPort       uint16
	dstPort       uint16
	dataOffset    uint16
	windowSize    uint16
	checksum      uint16
	urgentPointer uint16
	flags         uint16
	hdrLen        uint8
}

func (h TCPHeader) SetSrcPort(v uint16)    { setbe16(h[0:2], v) }
func (h TCPHeader) SetDstPort(v uint16)    { setbe16(h[2:4], v) }
func (h TCPHeader) SetSeq(v uint32)        { setbe32(h[4:8], v) }
func (h TCPHeader) SetAck(v uint32)        { setbe32(h[8:12], v) }
func (h TCPHeader) SetWindowSize(v uint16) { setbe16(h[14:16], v) }
func (h TCPHeader) SetChecksum(v uint16)   { setbe16(h[16:18], v) }
func (h TCPHeader) SetUrgentPtr(v uint16)  { setbe16(h[18:20], v) }

func (h TCPHeader) SetHdrLen(v uint8) {
	v = ((v >> 2) & 0x0f) << 4
	h[12] = (h[12] & 0x0f) | v
}

func (h TCPHeader) SetFlags(v uint16) {
	v &= 0x0fff
	h[12] = (h[12] & 0xf0) | uint8(v>>8)
	h[13] = uint8(v)
}

func (h TCPHeader) SrcPort() uint16         { return be16(h[0:2]) }
func (h TCPHeader) DstPort() uint16         { return be16(h[2:4]) }
func (h TCPHeader) Seq() uint32             { return be32(h[4:8]) }
func (h TCPHeader) Ack() uint32             { return be32(h[8:12]) }
func (h TCPHeader) HdrLen() uint8           { return (h[12] >> 4) << 2 }
func (h TCPHeader) WindowSize() uint16      { return be16(h[14:16]) }
func (h TCPHeader) Checksum() uint16        { return be16(h[16:18]) }
func (h TCPHeader) UrgentPtr() uint16       { return be16(h[18:20]) }
func (h TCPHeader) FlagIsSet(x uint16) bool { return h.Flags()&x == x }

func (h TCPHeader) Flags() uint16 {
	d := uint16(h[12]&0x0f) << 8
	return d | uint16(h[13])
}

func NewTCPHeader(b []byte) (TCPHeader, error) {

	h := TCPHeader(b)

	if len(b) < MinTCPHdrLen {
		return h, ErrShortBuffer
	}

	if h.HdrLen() < MinTCPHdrLen {
		return h, errors.New("invalid tcp header lenght")
	}

	if len(b) < int(h.HdrLen()) {
		return h, ErrShortBuffer
	}

	return h, nil
}

func (h *TCPHeaderInfo) SrcPort() uint16         { return h.srcPort }
func (h *TCPHeaderInfo) DstPort() uint16         { return h.dstPort }
func (h *TCPHeaderInfo) Seq() uint32             { return h.seqNum }
func (h *TCPHeaderInfo) Ack() uint32             { return h.ackNum }
func (h *TCPHeaderInfo) HdrLen() uint8           { return h.hdrLen }
func (h *TCPHeaderInfo) WindowSize() uint16      { return h.windowSize }
func (h *TCPHeaderInfo) Checksum() uint16        { return h.checksum }
func (h *TCPHeaderInfo) UrgentPtr() uint16       { return h.urgentPointer }
func (h *TCPHeaderInfo) FlagIsSet(x uint16) bool { return h.flags&x == x }
func (h *TCPHeaderInfo) Flags() uint16           { return h.flags }

func (h *TCPHeaderInfo) SetSrcPort(v uint16)    { h.srcPort = v }
func (h *TCPHeaderInfo) SetDstPort(v uint16)    { h.dstPort = v }
func (h *TCPHeaderInfo) SetSeq(v uint32)        { h.seqNum = v }
func (h *TCPHeaderInfo) SetAck(v uint32)        { h.ackNum = v }
func (h *TCPHeaderInfo) SetHdrLen(v uint8)      { h.hdrLen = v }
func (h *TCPHeaderInfo) SetWindowSize(v uint16) { h.windowSize = v }
func (h *TCPHeaderInfo) SetChecksum(v uint16)   { h.checksum = v }
func (h *TCPHeaderInfo) SetUrgentPtr(v uint16)  { h.urgentPointer = v }
func (h *TCPHeaderInfo) SetFlags(v uint16)      { h.flags = v }

func (h *TCPHeaderInfo) Encode(b []byte) error {

	if len(b) < MinTCPHdrLen {
		return ErrShortBuffer
	}

	switch {
	case h.HdrLen() < MinTCPHdrLen:
		fallthrough
	case h.HdrLen() > MaxTCPHdrLen:
		return errors.New("invalid tcp header lenght")
	}

	if len(b) < int(h.HdrLen()) {
		return ErrShortBuffer
	}

	tcpHdr := TCPHeader(b)
	tcpHdr.SetSrcPort(h.srcPort)
	tcpHdr.SetDstPort(h.dstPort)
	tcpHdr.SetSeq(h.seqNum)
	tcpHdr.SetAck(h.ackNum)
	tcpHdr.SetHdrLen(h.hdrLen)
	tcpHdr.SetWindowSize(h.windowSize)
	tcpHdr.SetChecksum(h.checksum)
	tcpHdr.SetUrgentPtr(h.urgentPointer)
	tcpHdr.SetFlags(h.flags)
	return nil
}

func (h *TCPHeaderInfo) Decode(b []byte) error {

	tcpHdr, err := NewTCPHeader(b)
	if err != nil {
		return err
	}

	h.srcPort = tcpHdr.SrcPort()
	h.dstPort = tcpHdr.DstPort()
	h.seqNum = tcpHdr.Seq()
	h.ackNum = tcpHdr.Ack()
	h.hdrLen = tcpHdr.HdrLen()
	h.windowSize = tcpHdr.WindowSize()
	h.checksum = tcpHdr.Checksum()
	h.urgentPointer = tcpHdr.UrgentPtr()
	h.flags = tcpHdr.Flags()
	return err
}
