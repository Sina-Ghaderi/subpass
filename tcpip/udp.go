package tcpip

import (
	"errors"
)

const FixUDPHdrLen = 0x08

type UDPHeader []byte

type UDPHeaderInfo struct {
	srcPort  uint16
	dstPort  uint16
	totalLen uint16
	checksum uint16
}

func (h UDPHeader) SrcPort() uint16  { return be16(h[0:2]) }
func (h UDPHeader) DstPort() uint16  { return be16(h[2:4]) }
func (h UDPHeader) TotalLen() uint16 { return be16(h[4:6]) }
func (h UDPHeader) Checksum() uint16 { return be16(h[6:8]) }

func (h UDPHeader) SetSrcPort(v uint16)  { setbe16(h[0:2], v) }
func (h UDPHeader) SetDstPort(v uint16)  { setbe16(h[2:4], v) }
func (h UDPHeader) SetTotalLen(v uint16) { setbe16(h[4:6], v) }
func (h UDPHeader) SetChecksum(v uint16) { setbe16(h[6:8], v) }

func (h *UDPHeaderInfo) SrcPort() uint16  { return h.srcPort }
func (h *UDPHeaderInfo) DstPort() uint16  { return h.dstPort }
func (h *UDPHeaderInfo) TotalLen() uint16 { return h.totalLen }
func (h *UDPHeaderInfo) Checksum() uint16 { return h.checksum }

func (h *UDPHeaderInfo) SetSrcPort(v uint16)  { h.srcPort = v }
func (h *UDPHeaderInfo) SetDstPort(v uint16)  { h.dstPort = v }
func (h *UDPHeaderInfo) SetTotalLen(v uint16) { h.totalLen = v }
func (h *UDPHeaderInfo) SetChecksum(v uint16) { h.checksum = v }

func NewUDPHeader(b []byte) (UDPHeader, error) {

	h := UDPHeader(b)

	if len(b) < FixUDPHdrLen {
		return h, ErrShortBuffer
	}

	totalLen := h.TotalLen()
	if totalLen < FixUDPHdrLen {
		return h, errors.New("invalid udp packet lenght")
	}

	if len(b) < int(totalLen) {
		return h, ErrShortBuffer
	}

	return h, nil

}

func (h *UDPHeaderInfo) Encode(b []byte) error {

	if len(b) < FixUDPHdrLen {
		return ErrShortBuffer
	}

	if h.TotalLen() < FixUDPHdrLen {
		return errors.New("invalid udp packet lenght")
	}

	if len(b) < int(h.TotalLen()) {
		return ErrShortBuffer
	}

	udpHdr := UDPHeader(b)
	udpHdr.SetSrcPort(h.srcPort)
	udpHdr.SetDstPort(h.dstPort)
	udpHdr.SetChecksum(h.checksum)
	udpHdr.SetTotalLen(h.totalLen)
	return nil
}

func (h *UDPHeaderInfo) Decode(b []byte) error {

	udpHdr, err := NewUDPHeader(b)
	if err != nil {
		return err
	}

	h.srcPort = udpHdr.SrcPort()
	h.dstPort = udpHdr.DstPort()
	h.checksum = udpHdr.Checksum()
	h.totalLen = udpHdr.TotalLen()
	return err
}
