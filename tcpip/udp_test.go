package tcpip

import (
	"bytes"
	"testing"
)

/*
UDP header (8 bytes):

SrcPort:  5353
DstPort:  53
Length:   32
Checksum: 0xbeef
*/

var rawUDP = []byte{
	0x14, 0xe9, // SrcPort = 5353
	0x00, 0x35, // DstPort = 53
	0x00, 0x20, // TotalLen = 32
	0xbe, 0xef, // Checksum

	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
}

/* ---------------- Decode ---------------- */

func TestUDPDecode(t *testing.T) {
	var h UDPHeaderInfo

	if err := h.Decode(rawUDP); err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if h.SrcPort() != 5353 {
		t.Fatal("bad src port")
	}
	if h.DstPort() != 53 {
		t.Fatal("bad dst port")
	}
	if h.TotalLen() != 32 {
		t.Fatal("bad total len")
	}
	if h.Checksum() != 0xbeef {
		t.Fatal("bad checksum")
	}
}

/* ---------------- Encode / Decode Roundtrip ---------------- */

func TestUDPEncodeDecodeRoundtrip(t *testing.T) {
	var h UDPHeaderInfo
	if err := h.Decode(rawUDP); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, h.TotalLen())
	if err := h.Encode(buf); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(buf, rawUDP) {
		t.Log("\n", buf, "\n", rawUDP)
		t.Fatal("encode output mismatch")

	}

	var out UDPHeaderInfo
	if err := out.Decode(buf); err != nil {
		t.Fatal(err)
	}

	if out.SrcPort() != h.SrcPort() ||
		out.DstPort() != h.DstPort() ||
		out.TotalLen() != h.TotalLen() ||
		out.Checksum() != h.Checksum() {
		t.Fatal("roundtrip mismatch")
	}
}

/* ---------------- Short Buffer Errors ---------------- */

func TestUDPDecodeShortBuffer(t *testing.T) {
	var h UDPHeaderInfo
	if err := h.Decode(rawUDP[:3]); err == nil {
		t.Fatal("expected short buffer error")
	}
}

func TestUDPShortPayload(t *testing.T) {
	h := make(UDPHeader, 10)
	setbe16(h[4:6], 12)

	if _, err := NewUDPHeader(h); err == nil {
		t.Fatal("expected short buffer error")
	}

}

func TestUDPInvalidLength(t *testing.T) {
	h := make(UDPHeader, 10)
	setbe16(h[4:6], 7)

	if _, err := NewUDPHeader(h); err == nil {
		t.Fatal("expected udp invalid length error")
	}

}

func TestUDPEncodeShortBuffer(t *testing.T) {
	var h UDPHeaderInfo
	h.Decode(rawUDP)

	if err := h.Encode(make([]byte, 3)); err == nil {
		t.Fatal("expected short buffer error")
	}
}

func TestUDPSetters(t *testing.T) {
	var h UDPHeaderInfo

	h.SetSrcPort(5353)
	h.SetDstPort(53)
	h.SetTotalLen(32)
	h.SetChecksum(0xbeef)

	if h.SrcPort() != 5353 {
		t.Fatal("SetSrcPort failed")
	}
	if h.DstPort() != 53 {
		t.Fatal("SetDstPort failed")
	}
	if h.TotalLen() != 32 {
		t.Fatal("SetTotalLen failed")
	}
	if h.Checksum() != 0xbeef {
		t.Fatal("SetChecksum failed")
	}
}

func TestUDPSettersEncode(t *testing.T) {
	var h UDPHeaderInfo

	h.SetSrcPort(5353)
	h.SetDstPort(53)
	h.SetTotalLen(32)
	h.SetChecksum(0xbeef)

	buf := make([]byte, h.TotalLen())
	if err := h.Encode(buf); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(buf, rawUDP) {
		t.Fatalf("encoded bytes mismatch\nexp=%v\ngot=%v", rawUDP, buf)
	}
}

func TestUDPSetterIsolation(t *testing.T) {
	var h UDPHeaderInfo

	h.SetSrcPort(1)
	h.SetDstPort(2)
	h.SetTotalLen(3)
	h.SetChecksum(4)

	h.SetSrcPort(100)

	if h.DstPort() != 2 {
		t.Fatal("SetSrcPort corrupted DstPort")
	}
	if h.TotalLen() != 3 {
		t.Fatal("SetSrcPort corrupted TotalLen")
	}
	if h.Checksum() != 4 {
		t.Fatal("SetSrcPort corrupted Checksum")
	}
}

func TestUDPPortsTable(t *testing.T) {
	tests := []struct {
		name string
		src  uint16
		dst  uint16
	}{
		{"dns", 5353, 53},
		{"ntp", 123, 123},
		{"ephemeral", 49152, 65535},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var h UDPHeaderInfo
			h.SetSrcPort(tt.src)
			h.SetDstPort(tt.dst)

			if h.SrcPort() != tt.src {
				t.Fatal("bad src port")
			}
			if h.DstPort() != tt.dst {
				t.Fatal("bad dst port")
			}
		})
	}
}
