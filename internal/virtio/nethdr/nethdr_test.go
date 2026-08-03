package nethdr

import (
	"encoding/binary"
	"math/rand"
	"testing"
)

// TestVirtioNetHdrLen locks in the wire size the rest of the codebase
// assumes everywhere (buffer sizing, offset arithmetic in gso/gro). The
// struct's field order (two 1-byte fields, then four 2-byte fields) is
// exactly what avoids compiler padding on every architecture Go supports -
// if that ever changes, this is the test that should catch it.
func TestVirtioNetHdrLen(t *testing.T) {
	if VirtioNetHdrLen != 10 {
		t.Fatalf("VirtioNetHdrLen = %d, want 10 (1+1+2+2+2+2, unpadded)", VirtioNetHdrLen)
	}
}

// TestFlagAndGsoTypeConstants pins the numeric values to the virtio-net
// spec. These are read/written directly as raw bytes to the kernel via the
// tun fd - a wrong constant here silently breaks interop with the kernel
// rather than failing loudly, so it's worth a dedicated test even though
// they're "just constants".
func TestFlagAndGsoTypeConstants(t *testing.T) {
	cases := []struct {
		name string
		got  int
		want int
	}{
		{"VIRTIO_NET_HDR_F_NEEDS_CSUM", VirtioNetHdrNeedsCsum, 0x1},
		{"VIRTIO_NET_HDR_F_DATA_VALID", VirtioNetHdrDataValid, 0x2},
		{"VIRTIO_NET_HDR_F_RSC_INFO", VirtioNetHdrRscInfo, 0x4},
		{"VIRTIO_NET_HDR_GSO_NONE", VirtioNetHdrGsoNone, 0x0},
		{"VIRTIO_NET_HDR_GSO_TCPV4", VirtioNetHdrGsoTcpV4, 0x1},
		{"VIRTIO_NET_HDR_GSO_UDP", VirtioNetHdrGsoUdp, 0x3},
		{"VIRTIO_NET_HDR_GSO_TCPV6", VirtioNetHdrGsoTcpV6, 0x4},
		{"VIRTIO_NET_HDR_GSO_UDP_L4", VirtioNetHdrGsoUdpL4, 0x5},
		{"VIRTIO_NET_HDR_GSO_ECN", VirtioNetHdrGsoEcn, 0x80},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %#x, want %#x", c.name, c.got, c.want)
		}
	}
}

// rawVnetHdrBytes lays out a virtio_net_hdr by hand, field by field, using
// the host's native endianness for the multi-byte fields - exactly how the
// kernel produces/consumes this structure over a tun fd. This is
// deliberately independent of VirtioNetHdr/Decode/Encode so the test has
// something external to check the unsafe-pointer-based implementation
// against.
func rawVnetHdrBytes(flags, gsoType uint8, hdrLen, gsoSize, csumStart, csumOffset uint16) []byte {
	b := make([]byte, VirtioNetHdrLen)
	b[0] = flags
	b[1] = gsoType
	binary.NativeEndian.PutUint16(b[2:4], hdrLen)
	binary.NativeEndian.PutUint16(b[4:6], gsoSize)
	binary.NativeEndian.PutUint16(b[6:8], csumStart)
	binary.NativeEndian.PutUint16(b[8:10], csumOffset)
	return b
}

func TestDecode_FieldByteOffsets(t *testing.T) {
	raw := rawVnetHdrBytes(0x1, 0x4, 0x1234, 0x5678, 0x9abc, 0xdef0)

	var v VirtioNetHdr
	if err := v.Decode(raw); err != nil {
		t.Fatalf("Decode: unexpected error: %v", err)
	}

	switch {
	case v.Flags != 0x1:
		t.Errorf("Flags = %#x, want 0x1", v.Flags)
	case v.GsoType != 0x4:
		t.Errorf("GsoType = %#x, want 0x4", v.GsoType)
	case v.HdrLen != 0x1234:
		t.Errorf("HdrLen = %#x, want 0x1234", v.HdrLen)
	case v.GsoSize != 0x5678:
		t.Errorf("GsoSize = %#x, want 0x5678", v.GsoSize)
	case v.CsumStart != 0x9abc:
		t.Errorf("CsumStart = %#x, want 0x9abc", v.CsumStart)
	case v.CsumOffset != 0xdef0:
		t.Errorf("CsumOffset = %#x, want 0xdef0", v.CsumOffset)
	}
}

func TestEncode_FieldByteOffsets(t *testing.T) {
	v := VirtioNetHdr{
		Flags:      0x2,
		GsoType:    0x5,
		HdrLen:     0x1111,
		GsoSize:    0x2222,
		CsumStart:  0x3333,
		CsumOffset: 0x4444,
	}

	got := make([]byte, VirtioNetHdrLen)
	if err := v.Encode(got); err != nil {
		t.Fatalf("Encode: unexpected error: %v", err)
	}

	want := rawVnetHdrBytes(0x2, 0x5, 0x1111, 0x2222, 0x3333, 0x4444)
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("byte %d: got %#02x, want %#02x (got=%x want=%x)", i, got[i], want[i], got, want)
		}
	}
}

// TestDecodeEncode_Symmetric checks Decode(Encode(v)) == v across a spread
// of field values, including the extremes of each field's range - this is
// exactly the kind of round-trip property that would catch an accidental
// swap of two field offsets, or a shift/mask typo, that per-field checks
// with "nice" values might miss.
func TestDecodeEncode_Symmetric(t *testing.T) {
	rng := rand.New(rand.NewSource(42))

	extremes := []uint16{0, 1, 0xff, 0x100, 0x7fff, 0x8000, 0xfffe, 0xffff}

	for i := 0; i < 500; i++ {
		var v VirtioNetHdr
		v.Flags = uint8(rng.Intn(256))
		v.GsoType = uint8(rng.Intn(256))
		if i < len(extremes)*4 {
			// Cycle through extreme values for the first chunk of
			// iterations so every field hits every boundary at least once.
			v.HdrLen = extremes[i%len(extremes)]
			v.GsoSize = extremes[(i/2)%len(extremes)]
			v.CsumStart = extremes[(i/3)%len(extremes)]
			v.CsumOffset = extremes[(i/5)%len(extremes)]
		} else {
			v.HdrLen = uint16(rng.Intn(65536))
			v.GsoSize = uint16(rng.Intn(65536))
			v.CsumStart = uint16(rng.Intn(65536))
			v.CsumOffset = uint16(rng.Intn(65536))
		}

		buf := make([]byte, VirtioNetHdrLen)
		if err := v.Encode(buf); err != nil {
			t.Fatalf("iter %d: Encode: %v", i, err)
		}

		var got VirtioNetHdr
		if err := got.Decode(buf); err != nil {
			t.Fatalf("iter %d: Decode: %v", i, err)
		}

		if got != v {
			t.Fatalf("iter %d: round trip mismatch: put %+v, got %+v", i, v, got)
		}
	}
}

func TestDecode_ShortBuffer(t *testing.T) {
	for n := 0; n < VirtioNetHdrLen; n++ {
		n := n
		t.Run("", func(t *testing.T) {
			b := make([]byte, n)
			// Poison the struct beforehand so we can confirm a short buffer
			// leaves it untouched rather than partially overwritten.
			sentinel := VirtioNetHdr{Flags: 0xaa, GsoType: 0xbb, HdrLen: 0xcccc,
				GsoSize: 0xdddd, CsumStart: 0xeeee, CsumOffset: 0xffff}
			v := sentinel

			err := v.Decode(b)
			if err == nil || err.Error() != "short nethdr buffer length" {
				t.Fatalf("len(b)=%d: err = %v, want 'short nethdr buffer length'", n, err)
			}
			if v != sentinel {
				t.Fatalf("len(b)=%d: struct mutated on short-buffer error: got %+v, want untouched %+v", n, v, sentinel)
			}
		})
	}

	// Exactly VirtioNetHdrLen must succeed - the off-by-one boundary right
	// above the short-buffer cases above.
	b := make([]byte, VirtioNetHdrLen)
	var v VirtioNetHdr
	if err := v.Decode(b); err != nil {
		t.Fatalf("len(b)=VirtioNetHdrLen: unexpected error: %v", err)
	}
}

func TestEncode_ShortBuffer(t *testing.T) {
	v := VirtioNetHdr{Flags: 1, GsoType: 1, HdrLen: 40, GsoSize: 1440, CsumStart: 20, CsumOffset: 16}

	for n := 0; n < VirtioNetHdrLen; n++ {
		n := n
		t.Run("", func(t *testing.T) {
			b := make([]byte, n)
			for i := range b {
				b[i] = 0x5a // sentinel pattern
			}
			err := v.Encode(b)
			if err == nil || err.Error() != "short nethdr buffer length" {
				t.Fatalf("len(b)=%d: err = %v, want short nethdr buffer length", n, err)
			}
			for i, x := range b {
				if x != 0x5a {
					t.Fatalf("len(b)=%d: byte %d mutated on short-buffer error: got %#x, want untouched 0x5a", n, i, x)
				}
			}
		})
	}
}

// TestDecode_IgnoresTrailingBytes verifies Decode only ever consumes the
// first VirtioNetHdrLen bytes of a longer buffer (e.g. vnet_hdr immediately
// followed by packet data in the same read buffer, which is exactly how
// gso/recv_offload.go calls it) and never reads or is affected by what
// comes after.
func TestDecode_IgnoresTrailingBytes(t *testing.T) {
	raw := rawVnetHdrBytes(1, 1, 40, 1440, 20, 16)
	trailer := []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22}
	full := append(append([]byte{}, raw...), trailer...)

	var v VirtioNetHdr
	if err := v.Decode(full); err != nil {
		t.Fatalf("Decode: unexpected error: %v", err)
	}
	want := VirtioNetHdr{Flags: 1, GsoType: 1, HdrLen: 40, GsoSize: 1440, CsumStart: 20, CsumOffset: 16}
	if v != want {
		t.Fatalf("got %+v, want %+v", v, want)
	}
}

// TestEncode_IgnoresTrailingCapacity mirrors the above for Encode: bytes
// beyond VirtioNetHdrLen in the destination must be left alone.
func TestEncode_IgnoresTrailingCapacity(t *testing.T) {
	v := VirtioNetHdr{Flags: 1, GsoType: 4, HdrLen: 60, GsoSize: 1220, CsumStart: 40, CsumOffset: 16}

	buf := make([]byte, VirtioNetHdrLen+8)
	for i := VirtioNetHdrLen; i < len(buf); i++ {
		buf[i] = 0x77
	}
	if err := v.Encode(buf); err != nil {
		t.Fatalf("Encode: unexpected error: %v", err)
	}
	for i := VirtioNetHdrLen; i < len(buf); i++ {
		if buf[i] != 0x77 {
			t.Fatalf("byte %d beyond VirtioNetHdrLen was touched: got %#x, want untouched 0x77", i, buf[i])
		}
	}

	var got VirtioNetHdr
	if err := got.Decode(buf); err != nil {
		t.Fatalf("Decode: unexpected error: %v", err)
	}
	if got != v {
		t.Fatalf("got %+v, want %+v", got, v)
	}
}

// TestZeroValueRoundTrips is a trivial but cheap sanity check: an
// all-zeros header (the common GSO_NONE, no-checksum-offload case) must
// decode/encode cleanly.
func TestZeroValueRoundTrips(t *testing.T) {
	buf := make([]byte, VirtioNetHdrLen)
	var v VirtioNetHdr
	if err := v.Decode(buf); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if v != (VirtioNetHdr{}) {
		t.Fatalf("got %+v, want zero value", v)
	}

	out := make([]byte, VirtioNetHdrLen)
	if err := v.Encode(out); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	for i, b := range out {
		if b != 0 {
			t.Fatalf("byte %d = %#x, want 0", i, b)
		}
	}
}
