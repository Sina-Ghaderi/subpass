package tcpip

import (
	"bytes"
	"testing"
)

/*
TCP header (20 bytes, no options):

SrcPort:  12345
DstPort:  80
Seq:      0x11223344
Ack:      0x55667788
DataOff:  5 (20 bytes)
Flags:    SYN | ACK
Window:   4096
Checksum: 0xabcd
Urgent:   0
*/

var rawTCP = []byte{
	0x30, 0x39, // SrcPort = 12345
	0x00, 0x50, // DstPort = 80

	0x11, 0x22, 0x33, 0x44, // Seq
	0x55, 0x66, 0x77, 0x88, // Ack

	0x50,                    // DataOffset=5, reserved
	TCPFlagSYN | TCPFlagACK, // Flags

	0x10, 0x00, // WindowSize = 4096
	0xab, 0xcd, // Checksum
	0x00, 0x00, // UrgentPtr
}

/* ---------------- Decode ---------------- */

func TestTCPDecode(t *testing.T) {
	var h TCPHeaderInfo

	if err := h.Decode(rawTCP); err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if h.SrcPort() != 12345 {
		t.Fatal("bad src port")
	}
	if h.DstPort() != 80 {
		t.Fatal("bad dst port")
	}
	if h.Seq() != 0x11223344 {
		t.Fatal("bad seq")
	}
	if h.Ack() != 0x55667788 {
		t.Fatal("bad ack")
	}
	if h.HdrLen() != 20 {
		t.Fatal("bad header len")
	}
	if h.WindowSize() != 4096 {
		t.Fatal("bad window size")
	}
	if h.Checksum() != 0xabcd {
		t.Fatal("bad checksum")
	}
	if h.UrgentPtr() != 0 {
		t.Fatal("bad urgent pointer")
	}
}

/* ---------------- Flags ---------------- */

func TestTCPFlags(t *testing.T) {
	var h TCPHeaderInfo
	h.Decode(rawTCP)

	flags := h.Flags()

	if flags&(TCPFlagSYN) == 0 {
		t.Fatal("SYN not set")
	}
	if flags&(TCPFlagACK) == 0 {
		t.Fatal("ACK not set")
	}
	if flags&(TCPFlagFIN) != 0 {
		t.Fatal("FIN should not be set")
	}

	if !h.FlagIsSet(TCPFlagSYN) {
		t.Fatal("FlagIsSet SYN failed")
	}
	if !h.FlagIsSet(TCPFlagACK) {
		t.Fatal("FlagIsSet ACK failed")
	}
	if h.FlagIsSet(TCPFlagFIN) {
		t.Fatal("FlagIsSet FIN should be false")
	}
}

/* ---------------- Encode / Decode Roundtrip ---------------- */

func TestTCPEncodeDecodeRoundtrip(t *testing.T) {
	var h TCPHeaderInfo
	if err := h.Decode(rawTCP); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, MinTCPHdrLen)
	if err := h.Encode(buf); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(buf, rawTCP[:MinTCPHdrLen]) {
		t.Fatal("encode output mismatch")
	}

	var out TCPHeaderInfo
	if err := out.Decode(buf); err != nil {
		t.Fatal(err)
	}

	if out.SrcPort() != h.SrcPort() ||
		out.DstPort() != h.DstPort() ||
		out.Seq() != h.Seq() ||
		out.Ack() != h.Ack() {
		t.Fatal("roundtrip mismatch")
	}
}

/* ---------------- Short Buffer Errors ---------------- */

func TestTCPDecodeShortBuffer(t *testing.T) {
	var h TCPHeaderInfo
	if err := h.Decode(rawTCP[:5]); err == nil {
		t.Fatal("expected short buffer error")
	}
}

func TestTCPEncodeShortBuffer(t *testing.T) {
	var h TCPHeaderInfo
	h.Decode(rawTCP)

	if err := h.Encode(make([]byte, 5)); err == nil {
		t.Fatal("expected short buffer error")
	}
}

func TestTCPHeaderFlagIsSet(t *testing.T) {
	var bb = make([]byte, MinTCPHdrLen)
	var bh = TCPHeader(bb)
	bh.SetFlags(TCPFlagFIN | TCPFlagACK)

	if !bh.FlagIsSet(TCPFlagFIN) {
		t.Fatal("expected FlagIsSet true")
	}
}

func TestTCPHeaderLengthShort(t *testing.T) {
	var bb = make([]byte, MinTCPHdrLen)
	var hdr = TCPHeader(bb)
	hdr.SetHdrLen(MinTCPHdrLen + 4)

	_, err := NewTCPHeader(bb)
	if err != ErrShortBuffer {
		t.Fatal("expected tcp header ErrShortBuffer error")
	}
}

func TestTCPHeaderInfoLengthShort(t *testing.T) {

	hdr := TCPHeaderInfo{}
	hdr.SetHdrLen(24)

	err := hdr.Encode(make([]byte, MinTCPHdrLen))
	if err == nil {
		t.Fatal("expected tcp header ErrShortBuffer error")
	}

}

/* ---------------- Header Length Variants ---------------- */

func TestTCPHeaderLengthVariants(t *testing.T) {
	var bb = make([]byte, MinTCPHdrLen)

	copy(bb[12:], []byte{0x60, 0x00})

	var bh = TCPHeader(bb)
	if bh.HdrLen() != 24 {
		t.Fatal("bad hdr len variant")
	}

}

func TestTCPHeaderInfoInvalidHeaderLength(t *testing.T) {

	hdr := TCPHeaderInfo{}
	hdr.SetHdrLen(10)

	err := hdr.Encode(make([]byte, MinTCPHdrLen))
	if err == nil {
		t.Fatal("expected tcp header invalid length error")
	}

}

func TestTCPHeaderLengthInvalid(t *testing.T) {
	var bb = make([]byte, MinTCPHdrLen)
	_, err := NewTCPHeader(bb)
	if err == nil {
		t.Fatal("expected tcp header length error")
	}

}

func TestTCPSetters16(t *testing.T) {
	var h TCPHeaderInfo

	h.SetSrcPort(1234)
	h.SetDstPort(80)
	h.SetWindowSize(4096)
	h.SetChecksum(0xabcd)
	h.SetUrgentPtr(9)

	if h.SrcPort() != 1234 {
		t.Fatal("SetSrcPort failed")
	}
	if h.DstPort() != 80 {
		t.Fatal("SetDstPort failed")
	}
	if h.WindowSize() != 4096 {
		t.Fatal("SetWindowSize failed")
	}
	if h.Checksum() != 0xabcd {
		t.Fatal("SetChecksum failed")
	}
	if h.UrgentPtr() != 9 {
		t.Fatal("SetUrgentPtr failed")
	}
}

func TestTCPSetters32(t *testing.T) {
	var h TCPHeaderInfo

	h.SetSeq(0x11223344)
	h.SetAck(0x55667788)

	if h.Seq() != 0x11223344 {
		t.Fatal("SetSeq failed")
	}
	if h.Ack() != 0x55667788 {
		t.Fatal("SetAck failed")
	}
}

func TestTCPSetHdrLen(t *testing.T) {
	var h TCPHeaderInfo

	h.SetFlags(TCPFlagSYN | TCPFlagACK)

	h.SetHdrLen(20)
	if h.HdrLen() != 20 {
		t.Fatalf("hdrlen expected 20 got %d", h.HdrLen())
	}

	if !h.FlagIsSet(TCPFlagSYN) || !h.FlagIsSet(TCPFlagACK) {
		t.Fatal("flags corrupted by SetHdrLen")
	}
}

func TestTCPSetFlags(t *testing.T) {
	var h TCPHeaderInfo

	h.SetHdrLen(20)
	h.SetFlags(TCPFlagSYN | TCPFlagACK)

	if !h.FlagIsSet(TCPFlagSYN) {
		t.Fatal("SYN not set")
	}
	if !h.FlagIsSet(TCPFlagACK) {
		t.Fatal("ACK not set")
	}
	if h.FlagIsSet(TCPFlagFIN) {
		t.Fatal("FIN should not be set")
	}

	if h.HdrLen() != 20 {
		t.Fatal("SetFlags corrupted header length")
	}
}

func TestTCPSettersEncode(t *testing.T) {
	var h TCPHeaderInfo

	h.SetSrcPort(12345)
	h.SetDstPort(80)
	h.SetSeq(0x11223344)
	h.SetAck(0x55667788)
	h.SetHdrLen(20)
	h.SetFlags(TCPFlagSYN | TCPFlagACK)
	h.SetWindowSize(4096)
	h.SetChecksum(0xabcd)
	h.SetUrgentPtr(0)

	buf := make([]byte, MinTCPHdrLen)
	if err := h.Encode(buf); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(buf, rawTCP) {
		t.Fatalf("encoded bytes mismatch\nexp=%v\ngot=%v", rawTCP, buf)
	}
}

func TestTCPFlagsTable(t *testing.T) {
	tests := []struct {
		name  string
		flags uint16
	}{
		{"SYN", TCPFlagSYN},
		{"ACK", TCPFlagACK},
		{"SYN|ACK", TCPFlagSYN | TCPFlagACK},
		{"FIN", TCPFlagFIN},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var h TCPHeaderInfo
			h.SetFlags(tt.flags)

			if h.Flags() != tt.flags {
				t.Fatalf("flags mismatch: got=%#x exp=%#x",
					h.Flags(), tt.flags)
			}
		})
	}
}
