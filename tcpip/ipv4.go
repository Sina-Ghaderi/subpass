package tcpip

import (
	"errors"
)

type IPv4Header []byte

type IPv4HeaderInfo struct {
	srcAddr    Addr
	dstAddr    Addr
	version    uint8
	hdrLen     uint8
	tos        uint8
	flags      uint8
	totalLen   uint16
	id         uint16
	fragOffset uint16
	ttl        uint8
	protocol   uint8
	checksum   uint16
}

func (h IPv4Header) Version() uint8     { return uint8(h[0] >> 4) }
func (h IPv4Header) HdrLen() uint8      { return (h[0] & 0x0f) << 2 }
func (h IPv4Header) ToS() uint8         { return h[1] }
func (h IPv4Header) TotalLen() uint16   { return be16(h[2:4]) }
func (h IPv4Header) ID() uint16         { return be16(h[4:6]) }
func (h IPv4Header) Flags() uint8       { return h[6] >> 5 }
func (h IPv4Header) FragOffset() uint16 { return be16(h[6:8]) & 0x1fff }
func (h IPv4Header) TTL() uint8         { return h[8] }
func (h IPv4Header) Protocol() uint8    { return h[9] }
func (h IPv4Header) Checksum() uint16   { return be16(h[10:12]) }

func (h IPv4Header) SrcAddr() (addr []byte) { return h[12:16] }
func (h IPv4Header) DstAddr() (addr []byte) { return h[16:20] }

func (h IPv4Header) SetVersion(v uint8) {
	h[0] = (h[0] & 0x0f) | ((v & 0x0f) << 4)
}

func (h IPv4Header) SetHdrLen(v uint8) {
	h[0] = (h[0] & 0xf0) | ((v >> 2) & 0x0f)
}

func (h IPv4Header) SetToS(v uint8)       { h[1] = v }
func (h IPv4Header) SetTotalLen(v uint16) { setbe16(h[2:4], v) }
func (h IPv4Header) SetID(v uint16)       { setbe16(h[4:6], v) }

func (h IPv4Header) SetFlags(v uint8) {
	f := uint16(v&0x07)<<13 | (be16(h[6:8]) & 0x1fff)
	setbe16(h[6:8], f)
}

func (h IPv4Header) SetFragOffset(v uint16) {
	setbe16(h[6:8], (v&0x1fff)|(be16(h[6:8])&0xe000))
}

func (h IPv4Header) SetTTL(v uint8)       { h[8] = v }
func (h IPv4Header) SetProtocol(v uint8)  { h[9] = v }
func (h IPv4Header) SetChecksum(v uint16) { setbe16(h[10:12], v) }

func (h IPv4Header) SetSrcAddr(addr []byte) { copy(h[12:16], addr) }
func (h IPv4Header) SetDstAddr(addr []byte) { copy(h[16:20], addr) }

func NewIPv4Header(b []byte) (IPv4Header, error) {

	var h = IPv4Header(b)

	switch {
	case len(b) < MinIPv4HdrLen:
		return h, ErrShortBuffer
	case b[0]>>4 != IPv4:
		return h, errors.New("invalid ipv4 header version")
	}

	totalLen, hdrLen := h.TotalLen(), h.HdrLen()

	switch {
	case hdrLen < MinIPv4HdrLen:
		return h, errors.New("invalid ipv4 header length")
	case totalLen < uint16(hdrLen):
		return h, errors.New("invalid ipv4 packet length")
	case len(b) < int(totalLen):
		return h, ErrShortBuffer
	}

	return h, nil
}

func (h *IPv4HeaderInfo) Version() uint8         { return h.version }
func (h *IPv4HeaderInfo) HdrLen() uint8          { return h.hdrLen }
func (h *IPv4HeaderInfo) ToS() uint8             { return h.tos }
func (h *IPv4HeaderInfo) TotalLen() uint16       { return h.totalLen }
func (h *IPv4HeaderInfo) ID() uint16             { return h.id }
func (h *IPv4HeaderInfo) Flags() uint8           { return h.flags }
func (h *IPv4HeaderInfo) FragOffset() uint16     { return h.fragOffset }
func (h *IPv4HeaderInfo) TTL() uint8             { return h.ttl }
func (h *IPv4HeaderInfo) Protocol() uint8        { return h.protocol }
func (h *IPv4HeaderInfo) Checksum() uint16       { return h.checksum }
func (h *IPv4HeaderInfo) SrcAddr() Addr          { return h.srcAddr }
func (h *IPv4HeaderInfo) DstAddr() Addr          { return h.dstAddr }
func (h *IPv4HeaderInfo) SetVersion(v uint8)     { h.version = v }
func (h *IPv4HeaderInfo) SetHdrLen(v uint8)      { h.hdrLen = v }
func (h *IPv4HeaderInfo) SetToS(v uint8)         { h.tos = v }
func (h *IPv4HeaderInfo) SetTotalLen(v uint16)   { h.totalLen = v }
func (h *IPv4HeaderInfo) SetID(v uint16)         { h.id = v }
func (h *IPv4HeaderInfo) SetFlags(v uint8)       { h.flags = v }
func (h *IPv4HeaderInfo) SetFragOffset(v uint16) { h.fragOffset = v }
func (h *IPv4HeaderInfo) SetTTL(v uint8)         { h.ttl = v }
func (h *IPv4HeaderInfo) SetProtocol(v uint8)    { h.protocol = v }
func (h *IPv4HeaderInfo) SetChecksum(v uint16)   { h.checksum = v }
func (h *IPv4HeaderInfo) SetSrcAddr(addr Addr)   { h.srcAddr = addr }
func (h *IPv4HeaderInfo) SetDstAddr(addr Addr)   { h.dstAddr = addr }

func (h *IPv4HeaderInfo) Encode(b []byte) error {

	switch {
	case len(b) < MinIPv4HdrLen:
		return ErrShortBuffer
	case h.version != IPv4:
		return errors.New("invalid ipv4 header version")
	}

	totalLen, hdrLen := h.TotalLen(), h.HdrLen()

	switch {
	case hdrLen < MinIPv4HdrLen:
		return errors.New("invalid ipv4 header length")
	case totalLen < uint16(hdrLen):
		return errors.New("invalid ipv4 packet length")
	case len(b) < int(totalLen):
		return ErrShortBuffer
	}

	ipHdr := IPv4Header(b)
	ipHdr.SetVersion(h.version)
	ipHdr.SetHdrLen(h.hdrLen)
	ipHdr.SetToS(h.tos)
	ipHdr.SetTotalLen(h.totalLen)
	ipHdr.SetID(h.id)
	ipHdr.SetFlags(h.flags)
	ipHdr.SetFragOffset(h.fragOffset)
	ipHdr.SetTTL(h.ttl)
	ipHdr.SetProtocol(h.protocol)
	ipHdr.SetChecksum(h.checksum)
	ipHdr.SetSrcAddr(h.srcAddr[:])
	ipHdr.SetDstAddr(h.dstAddr[:])

	return nil
}

func (h *IPv4HeaderInfo) Decode(b []byte) error {
	ipHdr, err := NewIPv4Header(b)
	if err != nil {
		return err
	}

	h.version = ipHdr.Version()
	h.hdrLen = ipHdr.HdrLen()
	h.tos = ipHdr.ToS()
	h.totalLen = ipHdr.TotalLen()
	h.id = ipHdr.ID()
	h.flags = ipHdr.Flags()
	h.fragOffset = ipHdr.FragOffset()
	h.ttl = ipHdr.TTL()
	h.protocol = ipHdr.Protocol()
	h.checksum = ipHdr.Checksum()
	copy(h.srcAddr[:IPv4AddrLen], ipHdr.SrcAddr())
	copy(h.dstAddr[:IPv4AddrLen], ipHdr.DstAddr())
	return err
}

// macro:
func (h *IPv4HeaderInfo) PayloadLen() uint16 { return h.totalLen - uint16(h.hdrLen) }
