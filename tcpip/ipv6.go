package tcpip

import (
	"errors"
	"unsafe"
)

type IPv6Header []byte

type IPv6HeaderInfo struct {
	srcAddr      Addr
	dstAddr      Addr
	flowLabel    uint32
	payloadLen   uint16
	nextHeader   uint8
	hopLimit     uint8
	version      uint8
	trafficClass uint8
}

func (h IPv6Header) Version() uint8 { return uint8(h[0] >> 4) }
func (h IPv6Header) TrafficClass() uint8 {
	return (h[0] << 4) | (h[1] >> 4)
}

func (h IPv6Header) FlowLabel() uint32 {
	return uint32(h[1]&0x0f)<<16 | uint32(h[2])<<8 | uint32(h[3])
}

func (h IPv6Header) PayloadLen() uint16     { return be16(h[4:6]) }
func (h IPv6Header) HopLimit() uint8        { return h[7] }
func (h IPv6Header) NextHeader() uint8      { return h[6] }
func (h IPv6Header) SrcAddr() (addr []byte) { return h[0x08:0x18] }
func (h IPv6Header) DstAddr() (addr []byte) { return h[0x18:0x28] }

func (h IPv6Header) SetVersion(v uint8) {
	h[0] = (h[0] & 0x0f) | ((v & 0x0f) << 4)
}

func (h IPv6Header) SetTrafficClass(v uint8) {
	h[0] = (h[0] & 0xf0) | (v >> 4)
	h[1] = (h[1] & 0x0f) | (v << 4)
}

func (h IPv6Header) SetFlowLabel(v uint32) {
	v &= 0x000fffff
	h[1] = (h[1] & 0xf0) | uint8(v>>16)
	h[2], h[3] = uint8(v>>8), uint8(v)
}

func (h IPv6Header) SetPayloadLen(v uint16) { setbe16(h[4:6], v) }
func (h IPv6Header) SetHopLimit(v uint8)    { h[7] = v }
func (h IPv6Header) SetNextHeader(v uint8)  { h[6] = v }

func (h IPv6Header) SetSrcAddr(addr []byte) {
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&h[0x08])), IPv6AddrLen), addr[:])
}

func (h IPv6Header) SetDstAddr(addr []byte) {
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&h[0x18])), IPv6AddrLen), addr[:])
}

func NewIPv6Header(b []byte) (IPv6Header, error) {

	h := IPv6Header(b)

	switch {
	case len(b) < FixIPv6HdrLen:
		return h, ErrShortBuffer
	case b[0]>>4 != IPv6:
		return h, errors.New("invalid ipv6 header version")
	}

	totalLen := FixIPv6HdrLen + int(h.PayloadLen())
	if len(b) < totalLen {
		return h, ErrShortBuffer
	}

	return h, nil
}

func (h *IPv6HeaderInfo) Version() uint8      { return h.version }
func (h *IPv6HeaderInfo) TrafficClass() uint8 { return h.trafficClass }
func (h *IPv6HeaderInfo) FlowLabel() uint32   { return h.flowLabel }
func (h *IPv6HeaderInfo) PayloadLen() uint16  { return h.payloadLen }
func (h *IPv6HeaderInfo) HopLimit() uint8     { return h.hopLimit }
func (h *IPv6HeaderInfo) NextHeader() uint8   { return h.nextHeader }
func (h *IPv6HeaderInfo) SrcAddr() Addr       { return h.srcAddr }
func (h *IPv6HeaderInfo) DstAddr() Addr       { return h.dstAddr }

func (h *IPv6HeaderInfo) SetVersion(v uint8)      { h.version = v }
func (h *IPv6HeaderInfo) SetTrafficClass(v uint8) { h.trafficClass = v }
func (h *IPv6HeaderInfo) SetFlowLabel(v uint32)   { h.flowLabel = v }
func (h *IPv6HeaderInfo) SetPayloadLen(v uint16)  { h.payloadLen = v }
func (h *IPv6HeaderInfo) SetHopLimit(v uint8)     { h.hopLimit = v }
func (h *IPv6HeaderInfo) SetNextHeader(v uint8)   { h.nextHeader = v }
func (h *IPv6HeaderInfo) SetSrcAddr(addr Addr)    { h.srcAddr = addr }
func (h *IPv6HeaderInfo) SetDstAddr(addr Addr)    { h.dstAddr = addr }

func (h *IPv6HeaderInfo) Decode(b []byte) error {

	ipHdr, err := NewIPv6Header(b)
	if err != nil {
		return err
	}

	h.version = ipHdr.Version()
	h.trafficClass = ipHdr.TrafficClass()
	h.flowLabel = ipHdr.FlowLabel()
	h.payloadLen = ipHdr.PayloadLen()
	h.hopLimit = ipHdr.HopLimit()
	h.nextHeader = ipHdr.NextHeader()
	copy(h.srcAddr[:], ipHdr.SrcAddr())
	copy(h.dstAddr[:], ipHdr.DstAddr())
	return err
}

func (h *IPv6HeaderInfo) Encode(b []byte) error {

	switch {
	case len(b) < FixIPv6HdrLen:
		return ErrShortBuffer
	case h.version != IPv6:
		return errors.New("invalid ipv6 header version")
	}

	totalLen := FixIPv6HdrLen + int(h.PayloadLen())
	if len(b) < totalLen {
		return ErrShortBuffer
	}

	ipHdr := IPv6Header(b)
	ipHdr.SetVersion(h.version)
	ipHdr.SetTrafficClass(h.trafficClass)
	ipHdr.SetFlowLabel(h.flowLabel)
	ipHdr.SetPayloadLen(h.payloadLen)
	ipHdr.SetHopLimit(h.hopLimit)
	ipHdr.SetNextHeader(h.nextHeader)
	ipHdr.SetDstAddr(h.dstAddr[:])
	ipHdr.SetSrcAddr(h.srcAddr[:])
	return nil

}
