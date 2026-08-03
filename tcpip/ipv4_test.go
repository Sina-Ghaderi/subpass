package tcpip

import (
	"bytes"
	"testing"
)

var rawIPv4 = []byte{
	0x45,       // Version=4, IHL=5
	0x10,       // ToS
	0x00, 0x54, // TotalLen = 84
	0x12, 0x34, // ID
	0x40, 0x00, // Flags=DF, FragOffset=0
	0x40,       // TTL
	0x06,       // Protocol TCP
	0xab, 0xcd, // Checksum
	192, 168, 1, 1, // Src
	8, 8, 8, 8, // Dst

	// payload
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
}

func TestIPv4Decode(t *testing.T) {
	var h IPv4HeaderInfo
	if err := h.Decode(rawIPv4); err != nil {
		t.Fatal(err)
	}

	if h.Version() != IPv4 {
		t.Fatal("bad version")
	}
	if h.HdrLen() != MinIPv4HdrLen {
		t.Fatal("bad hdr len")
	}
	if h.ToS() != 0x10 {
		t.Fatal("bad tos")
	}
	if h.TotalLen() != 84 {
		t.Fatal("bad total len")
	}
	if h.ID() != 0x1234 {
		t.Fatal("bad id")
	}
	if h.Flags()&IPv4FlagDF != IPv4FlagDF {
		t.Fatal("DF flag not set")
	}
	if h.TTL() != 64 {
		t.Fatal("bad ttl")
	}
	if h.Protocol() != ProtoTCP {
		t.Fatal("bad protocol")
	}
	if h.Checksum() != 0xabcd {
		t.Fatal("bad checksum")
	}

	src := h.SrcAddr()
	dst := h.DstAddr()

	if !bytes.Equal(src[:4], []byte{192, 168, 1, 1}) {
		t.Fatal("bad src")
	}
	if !bytes.Equal(dst[:4], []byte{8, 8, 8, 8}) {
		t.Fatal("bad dst")
	}

}

func TestIPv4EncodeDecodeRoundtrip(t *testing.T) {
	var h IPv4HeaderInfo
	h.Decode(rawIPv4)

	buf := make([]byte, h.TotalLen())
	if err := h.Encode(buf); err != nil {
		t.Fatal(err)
	}

	var out IPv4HeaderInfo
	if err := out.Decode(buf); err != nil {
		t.Fatal(err)
	}

	if out.ID() != h.ID() || out.TTL() != h.TTL() {
		t.Fatal("roundtrip mismatch")
	}
}

func TestIPv4Setters(t *testing.T) {
	var h IPv4HeaderInfo
	h.SetVersion(IPv4)
	h.SetHdrLen(20)
	h.SetToS(0xaa)
	h.SetTotalLen(60)
	h.SetID(0xbeef)
	h.SetFlags(IPv4FlagMF)
	h.SetFragOffset(123)
	h.SetTTL(42)
	h.SetProtocol(ProtoUDP)
	h.SetChecksum(0xdead)

	var a Addr
	copy(a[:4], []byte{1, 2, 3, 4})
	h.SetSrcAddr(a)
	copy(a[:4], []byte{5, 6, 7, 8})
	h.SetDstAddr(a)

	if h.ToS() != 0xaa || h.ID() != 0xbeef || h.TTL() != 42 {
		t.Fatal("setter failed")
	}
}

func TestIPv4FlagsAndFragIsolation(t *testing.T) {
	var h IPv4HeaderInfo
	h.SetVersion(IPv4)
	h.SetHdrLen(20)
	h.SetTotalLen(60)

	h.SetFlags(IPv4FlagDF)
	h.SetFragOffset(1234)

	if h.Flags() != IPv4FlagDF {
		t.Fatal("flags corrupted by frag offset")
	}
	if h.FragOffset() != 1234 {
		t.Fatal("frag offset corrupted by flags")
	}
}

func TestIPv4EncodeErrors(t *testing.T) {
	var h IPv4HeaderInfo

	// wrong version
	h.SetVersion(IPv6)
	if err := h.Encode(make([]byte, 20)); err == nil {
		t.Fatal("expected version error")
	}

	h.SetVersion(IPv4)
	h.SetHdrLen(16)
	if err := h.Encode(make([]byte, 20)); err == nil {
		t.Fatal("expected hdr len error")
	}

	h.SetHdrLen(20)
	h.SetTotalLen(10)
	if err := h.Encode(make([]byte, 20)); err == nil {
		t.Fatal("expected total len error")
	}

	h.SetTotalLen(60)
	if err := h.Encode(make([]byte, 10)); err == nil {
		t.Fatal("expected short buffer error")
	}

	if err := h.Encode(make([]byte, 22)); err == nil {
		t.Fatal("expected short buffer error")
	}
}

func TestIPv4DecodeErrors(t *testing.T) {
	var h IPv4HeaderInfo

	b := append([]byte{}, rawIPv4...)
	b[0] = 0x60
	if err := h.Decode(b); err == nil {
		t.Fatal("expected invalid version")
	}

	b = append([]byte{}, rawIPv4...)
	b[0] = 0x41
	if err := h.Decode(b); err == nil {
		t.Fatal("expected invalid hdr len")
	}

	b = append([]byte{}, rawIPv4...)
	setbe16(b[2:4], 10)
	if err := h.Decode(b); err == nil {
		t.Fatal("expected invalid total len")
	}

	if err := h.Decode(rawIPv4[:10]); err == nil {
		t.Fatal("expected short buffer")
	}

	if err := h.Decode(rawIPv4[:20]); err == nil {
		t.Fatal("expected short buffer")
	}
}
