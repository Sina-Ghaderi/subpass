package tcpip

import (
	"testing"
)

var rawIPv6 = []byte{
	0x60, 0x00, 0x00, 0x00,
	0x00, 0x20,
	ProtoTCP,
	64,

	// Src
	0x20, 0x01, 0x0d, 0xb8,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 1,

	// Dst
	0x20, 0x01, 0x0d, 0xb8,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 2,

	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
}

func TestIPv6Decode(t *testing.T) {
	var h IPv6HeaderInfo
	if err := h.Decode(rawIPv6); err != nil {
		t.Fatal(err)
	}

	if h.Version() != IPv6 {
		t.Fatal("bad version")
	}
	if h.TrafficClass() != 0 {
		t.Fatal("bad tc")
	}
	if h.FlowLabel() != 0 {
		t.Fatal("bad flow label")
	}
	if h.PayloadLen() != 32 {
		t.Fatal("bad payload len")
	}
	if h.NextHeader() != ProtoTCP {
		t.Fatal("bad next header")
	}
	if h.HopLimit() != 64 {
		t.Fatal("bad hop limit")
	}

	if h.SrcAddr()[15] != 1 || h.DstAddr()[15] != 2 {
		t.Fatal("bad addr")
	}
}

func TestIPv6Setters(t *testing.T) {
	var h IPv6HeaderInfo
	h.SetVersion(IPv6)
	h.SetTrafficClass(0xaa)
	h.SetFlowLabel(0xabcde)
	h.SetPayloadLen(123)
	h.SetHopLimit(42)
	h.SetNextHeader(ProtoUDP)

	if h.TrafficClass() != 0xaa {
		t.Fatal("bad tc")
	}
	if h.FlowLabel() != 0xabcde {
		t.Fatal("bad flow label")
	}
	if h.PayloadLen() != 123 {
		t.Fatal("bad payload len")
	}
}

func TestIPv6TrafficClassBits(t *testing.T) {
	var h IPv6HeaderInfo
	h.SetVersion(IPv6)

	h.SetTrafficClass(0xab)
	if h.TrafficClass() != 0xab {
		t.Fatalf("tc mismatch: %#x", h.TrafficClass())
	}
}

func TestIPv6FlowLabelMasking(t *testing.T) {

	var h IPv6Header = make(IPv6Header, FixIPv6HdrLen)
	h.SetVersion(IPv6)

	h.SetFlowLabel(0xffffffff)

	if h.FlowLabel() != 0x000fffff {
		t.Fatal("flow label not masked")
	}

}

func TestIPv6EncodeErrors(t *testing.T) {
	var h IPv6HeaderInfo
	h.SetVersion(IPv4)

	if err := h.Encode(make([]byte, FixIPv6HdrLen)); err == nil {
		t.Fatal("expected version error")
	}

	h.SetVersion(IPv6)
	h.SetPayloadLen(100)
	if err := h.Encode(make([]byte, FixIPv6HdrLen)); err == nil {
		t.Fatal("expected short buffer")
	}

	if err := h.Encode(make([]byte, 5)); err == nil {
		t.Fatal("expected short buffer")
	}
}

func TestIPv6DecodeErrors(t *testing.T) {
	var h IPv6HeaderInfo

	if err := h.Decode(rawIPv6[:10]); err == nil {
		t.Fatal("expected short buffer")
	}

	b := append([]byte{}, rawIPv6...)
	b[0] = 0x40
	if err := h.Decode(b); err == nil {
		t.Fatal("expected invalid version")
	}

	b = append([]byte{}, rawIPv6...)
	setbe16(b[4:6], 1000)
	if err := h.Decode(b); err == nil {
		t.Fatal("expected payload overflow")
	}
}

func TestIPv6AddrSetGet(t *testing.T) {
	var h IPv6HeaderInfo
	h.SetVersion(IPv6)

	var a Addr
	for i := 0; i < 16; i++ {
		a[i] = byte(i)
	}

	h.SetSrcAddr(a)
	h.SetDstAddr(a)

	if h.SrcAddr() != a || h.DstAddr() != a {
		t.Fatal("addr mismatch")
	}
}
