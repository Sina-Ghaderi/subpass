package tcpip

import "testing"

func Fuzz01IPv4Decode(f *testing.F) {
	f.Add(rawIPv4)

	f.Fuzz(func(t *testing.T, b []byte) {
		var h IPv4HeaderInfo
		_ = h.Decode(b)
	})
}

func Fuzz02IPv6Decode(f *testing.F) {
	f.Add(rawIPv6)

	f.Fuzz(func(t *testing.T, b []byte) {
		var h IPv6HeaderInfo
		_ = h.Decode(b)
	})
}

func Fuzz03IPv4Roundtrip(f *testing.F) {
	f.Add(rawIPv4)

	f.Fuzz(func(t *testing.T, b []byte) {
		var h IPv4HeaderInfo
		if h.Decode(b) != nil {
			return
		}

		buf := make([]byte, h.TotalLen())
		if h.Encode(buf) != nil {
			return
		}

		var out IPv4HeaderInfo
		if out.Decode(buf) != nil {
			t.Fatalf("roundtrip failed")
		}
	})
}

func Fuzz04IPv6Fields(f *testing.F) {
	f.Fuzz(func(t *testing.T,
		tc uint8,
		flow uint32,
		pl uint16,
		hl uint8,
	) {
		var h IPv6HeaderInfo
		h.SetVersion(IPv6)
		h.SetTrafficClass(tc)
		h.SetFlowLabel(flow)
		h.SetPayloadLen(pl)
		h.SetHopLimit(hl)

		if h.FlowLabel() != (flow & 0x000fffff) {
			t.Fatalf("flow invariant broken")
		}
	})
}

func Fuzz05IPv4DecodeEncode(f *testing.F) {
	f.Add(rawIPv4)

	f.Fuzz(func(t *testing.T, b []byte) {
		var h IPv4HeaderInfo
		if err := h.Decode(b); err != nil {
			return
		}

		buf := make([]byte, h.TotalLen())
		if err := h.Encode(buf); err != nil {
			t.Fatalf("encode failed after decode")
		}

		var out IPv4HeaderInfo
		if err := out.Decode(buf); err != nil {
			t.Fatalf("roundtrip failed")
		}
	})
}

func Fuzz06IPv6DecodeEncode(f *testing.F) {
	f.Add(rawIPv6)

	f.Fuzz(func(t *testing.T, b []byte) {
		var h IPv6HeaderInfo
		if err := h.Decode(b); err != nil {
			return
		}

		buf := make([]byte, h.PayloadLen()+FixIPv6HdrLen)
		if err := h.Encode(buf); err != nil {
			t.Fatalf("encode failed after decode")
		}

		var out IPv6HeaderInfo
		if err := out.Decode(buf); err != nil {
			t.Fatalf("roundtrip failed: %v\n", err)
		}
	})
}

func Fuzz07IPv4_Decode(f *testing.F) {
	f.Add([]byte{
		0x45, 0x00, 0x00, 0x14,
		0x00, 0x01, 0x00, 0x00,
		64, ProtoTCP, 0x00, 0x00,
		1, 2, 3, 4,
		5, 6, 7, 8,
	})

	f.Fuzz(func(t *testing.T, b []byte) {
		var h IPv4HeaderInfo
		_ = h.Decode(b)
	})
}

func Fuzz08IPv4_Roundtrip(f *testing.F) {
	f.Add(uint8(IPv4), uint8(20), uint16(20), uint8(64), uint8(ProtoUDP))

	f.Fuzz(func(t *testing.T, ver, hdrLen uint8, total uint16, ttl, proto uint8) {
		var h IPv4HeaderInfo

		h.SetVersion(ver)
		h.SetHdrLen(hdrLen)
		h.SetTotalLen(total)
		h.SetTTL(ttl)
		h.SetProtocol(proto)

		buf := make([]byte, MaxIPv4HdrLen)
		if err := h.Encode(buf); err != nil {
			return
		}

		var out IPv4HeaderInfo
		if err := out.Decode(buf); err != nil {
			t.Fatalf("decode failed: %v", err)
		}

		if out.Version() != h.Version() ||
			out.HdrLen() != h.HdrLen() ||
			out.TotalLen() != h.TotalLen() ||
			out.TTL() != h.TTL() ||
			out.Protocol() != h.Protocol() {
			t.Fatal("roundtrip mismatch")
		}
	})
}

func Fuzz09IPv4_FlagsFrag(f *testing.F) {
	f.Add(uint8(3), uint16(0x1234))

	f.Fuzz(func(t *testing.T, flags uint8, off uint16) {
		var h IPv4HeaderInfo

		h.SetFlags(flags)
		h.SetFragOffset(off)

		if h.Flags() != (flags & 0x07) {
			t.Fatal("flags invariant broken")
		}
		if h.FragOffset() != (off & 0x1fff) {
			t.Fatal("frag offset invariant broken")
		}
	})
}

func Fuzz10IPv4_Addr(f *testing.F) {
	f.Add([]byte{1, 2, 3, 4}, []byte{5, 6, 7, 8})

	f.Fuzz(func(t *testing.T, s, d []byte) {
		if len(s) < IPv4AddrLen || len(d) < IPv4AddrLen {
			return
		}

		var h IPv4HeaderInfo
		var sa, da Addr

		copy(sa[:4], s)
		copy(da[:4], d)

		h.SetSrcAddr(sa)
		h.SetDstAddr(da)

		if h.SrcAddr() != sa {
			t.Fatalf("src addr mismatch: %v %v\n", h.SrcAddr(), sa)
		}
		if h.DstAddr() != da {
			t.Fatal("dst addr mismatch")
		}
	})
}

func Fuzz11IPv4_ShortBuffer(f *testing.F) {
	f.Add([]byte{0x45})

	f.Fuzz(func(t *testing.T, b []byte) {
		var h IPv4HeaderInfo
		if len(b) < MinIPv4HdrLen {
			if err := h.Decode(b); err == nil {
				t.Fatal("expected error on short buffer")
			}
		}
	})
}

func Fuzz12IPv6_Decode(f *testing.F) {
	f.Add(make([]byte, FixIPv6HdrLen))

	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 0 {
			b[0] = (IPv6 << 4)
		}
		var h IPv6HeaderInfo
		_ = h.Decode(b)
	})
}

func Fuzz13IPv6_Roundtrip(f *testing.F) {
	f.Add(uint8(IPv6), uint8(0xaa), uint32(0xabcde), uint16(1280))

	f.Fuzz(func(t *testing.T, ver uint8, tc uint8, fl uint32, plen uint16) {
		var h IPv6HeaderInfo

		h.SetVersion(ver)
		h.SetTrafficClass(tc)
		h.SetFlowLabel(fl)
		h.SetPayloadLen(plen)
		h.SetHopLimit(64)
		h.SetNextHeader(ProtoTCP)

		buf := make([]byte, FixIPv6HdrLen+int(plen))
		if err := h.Encode(buf); err != nil {
			return
		}

		var out IPv6HeaderInfo
		if err := out.Decode(buf); err != nil {
			t.Fatal(err)
		}

		if out.Version() != IPv6 ||
			out.TrafficClass() != tc ||
			out.FlowLabel() != (fl&0x000fffff) ||
			out.PayloadLen() != plen {
			t.Fatal("ipv6 roundtrip mismatch")
		}
	})
}

func Fuzz14IPv6_TC_Flow(f *testing.F) {
	f.Add(uint8(0xff), uint32(0xffffffff))

	f.Fuzz(func(t *testing.T, tc uint8, fl uint32) {
		var h = make(IPv6Header, FixIPv6HdrLen)

		h.SetTrafficClass(tc)
		h.SetFlowLabel(fl)

		if h.TrafficClass() != tc {
			t.Fatal("traffic class mismatch")
		}
		if h.FlowLabel() != (fl & 0x000fffff) {
			t.Fatal("flow label invariant broken")
		}
	})
}

func Fuzz15IPv6_Addr(f *testing.F) {
	f.Add(make([]byte, 16), make([]byte, 16))

	f.Fuzz(func(t *testing.T, s, d []byte) {
		if len(s) < IPv6AddrLen || len(d) < IPv6AddrLen {
			return
		}

		var h IPv6HeaderInfo
		var sa, da Addr

		copy(sa[:], s)
		copy(da[:], d)

		h.SetSrcAddr(sa)
		h.SetDstAddr(da)

		if h.SrcAddr() != sa {
			t.Fatal("src addr mismatch")
		}
		if h.DstAddr() != da {
			t.Fatal("dst addr mismatch")
		}
	})
}

func Fuzz16IPv6_ShortBuffer(f *testing.F) {
	f.Add([]byte{0x60})

	f.Fuzz(func(t *testing.T, b []byte) {
		var h IPv6HeaderInfo
		if len(b) < FixIPv6HdrLen {
			if err := h.Decode(b); err == nil {
				t.Fatal("expected short buffer error")
			}
		}
	})
}
