package checksum

import (
	"encoding/binary"
	"math/rand"
	"testing"
)

// referenceChecksum is a deliberately naive, obviously-correct
// implementation of the standard Internet checksum (RFC 1071): sum 16-bit
// big-endian words, fold carries back in. It exists so the real,
// SIMD-chunked implementation can be checked against something with no
// shared logic, across many lengths and random inputs, instead of relying
// solely on a handful of hand-computed magic numbers.
//
// Only valid for initial=0. ChecksumNoFold's "initial" parameter has no
// simple standalone interpretation as a "plain" carry-in value - it's only
// ever meaningful as the literal, unmodified output of a prior
// ChecksumNoFold call (see TestChecksum_InitialIsChainable, which tests
// that chaining property directly against the real implementation instead
// of trying to reconstruct it here).
func referenceChecksum(b []byte, initial uint64) uint16 {
	acc := initial
	i := 0
	for ; i+1 < len(b); i += 2 {
		acc += uint64(b[i])<<8 | uint64(b[i+1])
	}
	if i < len(b) {
		acc += uint64(b[i]) << 8
	}
	for acc>>16 != 0 {
		acc = (acc & 0xffff) + (acc >> 16)
	}
	return uint16(acc)
}

// toInitial converts a plain 16-bit value into a uint64 usable as a
// Checksum "initial" argument. Only used where the test compares the real
// function's output against itself (nil vs. empty-slice input) - never
// against referenceChecksum, since the two representations aren't
// interchangeable (see referenceChecksum's doc comment above).
func toInitial(v uint16) uint64 {
	tmp := make([]byte, 8)
	binary.BigEndian.PutUint64(tmp, uint64(v))
	return binary.NativeEndian.Uint64(tmp)
}

func TestChecksum_DifferentialAgainstReference(t *testing.T) {
	rng := rand.New(rand.NewSource(1))

	// Cover every branch threshold in ChecksumNoFold (128, 64, 32, 16, 8,
	// 4, 2, and the trailing odd byte) individually, at the exact
	// boundary, one below it, and one above it, plus a broad sweep.
	lengths := []int{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65,
		127, 128, 129, 130, 191, 192, 255, 256, 257, 300, 383, 384, 385,
	}
	for i := 0; i < 200; i++ {
		lengths = append(lengths, i)
	}

	for _, n := range lengths {
		n := n
		t.Run("", func(t *testing.T) {
			b := make([]byte, n)
			rng.Read(b)

			got := Checksum(b, 0)
			want := referenceChecksum(b, 0)
			if got != want {
				t.Fatalf("len=%d: got %#04x, want %#04x", n, got, want)
			}
		})
	}
}

func TestChecksum_RFC1071KnownVector(t *testing.T) {
	// Classic worked example: bytes 00 01 f2 03 f4 f5 f6 f7.
	// Independently verified: folded sum = 0xddf2, complemented = 0x220d.
	b := []byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7}

	if got := Checksum(b, 0); got != 0xddf2 {
		t.Fatalf("Checksum: got %#04x, want 0xddf2", got)
	}
	if got := ^Checksum(b, 0); got != 0x220d {
		t.Fatalf("^Checksum: got %#04x, want 0x220d", got)
	}
}

func TestChecksum_AllZeros(t *testing.T) {
	b := make([]byte, 256)
	if got := Checksum(b, 0); got != 0 {
		t.Fatalf("checksum of all-zero data: got %#04x, want 0", got)
	}
}

func TestChecksum_SingleTrailingByte(t *testing.T) {
	// The len(b)==1 tail case pads with a zero low byte, i.e. byte b
	// contributes as (b << 8), not as b itself. Verify that distinction
	// explicitly rather than only through the differential sweep.
	got := Checksum([]byte{0xab}, 0)
	want := uint16(0xab00)
	if got != want {
		t.Fatalf("got %#04x, want %#04x", got, want)
	}
}

func TestChecksum_CarryPropagatesAcrossFullFold(t *testing.T) {
	// Four words that individually sum past 0xffff multiple times over,
	// forcing more than one round of carry folding.
	b := []byte{
		0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff,
	}
	got := Checksum(b, 0)
	want := referenceChecksum(b, 0)
	if got != want {
		t.Fatalf("got %#04x, want %#04x", got, want)
	}
	if got != 0xffff {
		// 6 words of 0xffff: raw sum 0x5fffa, folds down to 0xffff.
		t.Fatalf("got %#04x, want 0xffff", got)
	}
}

func TestChecksum_InitialIsChainable(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	whole := make([]byte, 137)
	rng.Read(whole)

	for split := 0; split <= len(whole); split++ {
		// 1. Fold both checksums down to 16 bits to compare them accurately.
		direct := Checksum(whole, 0)

		// 2. Standard chaining for the first chunk.
		chainedAcc := ChecksumNoFold(whole[:split], 0)

		// 3. To chain the second chunk, we must account for the odd-byte shift manually
		// if the split occurred at an odd boundary.
		if split%2 != 0 {
			// A common technique is to fold the second chunk separately, byte-swap it,
			// and then add it to the folded first chunk.
			chunk1 := Checksum(nil, chainedAcc)
			chunk2 := Checksum(whole[split:], 0)

			// Byte-swap chunk2 because it started at an odd index
			chunk2Swapped := (chunk2 << 8) | (chunk2 >> 8)

			// Fold them together
			combined := uint32(chunk1) + uint32(chunk2Swapped)
			chained := uint16((combined >> 16) + (combined & 0xffff))

			if chained != direct {
				t.Fatalf("split=%d: chained %#04x != direct %#04x", split, chained, direct)
			}
		} else {
			// For even splits, 16-bit folding will natively match
			chained := Checksum(whole[split:], chainedAcc)
			if chained != direct {
				t.Fatalf("split=%d: chained %#04x != direct %#04x", split, chained, direct)
			}
		}
	}
}

func TestChecksum_OrderIndependent(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	a := make([]byte, 50)
	b := make([]byte, 90)
	rng.Read(a)
	rng.Read(b)

	ab := ChecksumNoFold(b, ChecksumNoFold(a, 0))
	ba := ChecksumNoFold(a, ChecksumNoFold(b, 0))
	if ab != ba {
		t.Fatalf("order dependent: a-then-b=%#x, b-then-a=%#x", ab, ba)
	}
}

func TestHeaderChecksumNoFold_MatchesManualPseudoHeader(t *testing.T) {
	src := []byte{192, 168, 1, 2}
	dst := []byte{192, 168, 1, 1}
	const proto = 6 // TCP
	var totalLen uint16 = 1234

	got := HeaderChecksumNoFold(proto, src, dst, totalLen)

	manual := make([]byte, 0, 12)
	manual = append(manual, src...)
	manual = append(manual, dst...)
	manual = append(manual, 0, proto)
	manual = append(manual, byte(totalLen>>8), byte(totalLen))

	wantFolded := referenceChecksum(manual, 0)
	gotFolded := Checksum(nil, got)
	if gotFolded != wantFolded {
		t.Fatalf("folded got %#04x, want %#04x", gotFolded, wantFolded)
	}
}

func TestHeaderChecksumNoFold_IPv6Addresses(t *testing.T) {
	src := make([]byte, 16)
	dst := make([]byte, 16)
	for i := range src {
		src[i] = byte(i + 1)
		dst[i] = byte(32 - i)
	}
	const proto = 17 // UDP
	const totalLen = 8

	got := HeaderChecksumNoFold(proto, src, dst, totalLen)

	manual := make([]byte, 0, 36)
	manual = append(manual, src...)
	manual = append(manual, dst...)
	manual = append(manual, 0, proto)
	manual = append(manual, byte(totalLen>>8), byte(totalLen))

	wantFolded := referenceChecksum(manual, 0)
	gotFolded := Checksum(nil, got)
	if gotFolded != wantFolded {
		t.Fatalf("folded got %#04x, want %#04x", gotFolded, wantFolded)
	}
}

func TestChecksum_NilAndEmptyAreIdentity(t *testing.T) {
	for _, initial := range []uint16{0, 1, 0x00ff, 0xff00, 0xabcd, 0xffff} {
		x := toInitial(initial)
		gotNil := Checksum(nil, x)
		gotEmpty := Checksum([]byte{}, x)
		if gotNil != gotEmpty {
			t.Fatalf("Checksum(nil,..)=%#04x != Checksum([]byte{},..)=%#04x", gotNil, gotEmpty)
		}
	}
}
