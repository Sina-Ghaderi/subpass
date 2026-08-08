package tcpip

import (
	"errors"
)

const IPv4AddrLen = 0x04
const IPv6AddrLen = 0x10

type Addr [16]byte

const (
	IPv4 = 0x04
	IPv6 = 0x06
)

const MinIPv4HdrLen = 0x14
const MaxIPv4HdrLen = 0x3c
const FixIPv6HdrLen = 0x28

const (
	ProtoTCP = 0x06
	ProtoUDP = 0x11
)

const (
	IPv4FlagMF = 1 << iota
	IPv4FlagDF
)

func Version(b []byte) (v uint8, err error) {
	if len(b) < 1 {
		return v, ErrShortBuffer
	}

	v = b[0] >> 4
	if v == IPv4 || v == IPv6 {
		return
	}

	return v, errors.New("invalid ip header version")
}

func TotalLen(b []byte) (int, error) {

	ipv, err := Version(b)
	if err != nil {
		return 0, err
	}

	if ipv == IPv4 {
		return IPv4TotalLen(b)
	} else {
		return IPv6TotalLen(b)
	}
}

func IPv4TotalLen(b []byte) (int, error) {

	if len(b) < MinIPv4HdrLen {
		return 0, ErrShortBuffer
	}

	var err error

	totalLen, hdrLen := be16(b[2:4]), (b[0]&0x0f)<<2

	switch {
	case hdrLen < MinIPv4HdrLen:
		err = errors.New("invalid ipv4 header length")
		totalLen = 0
	case totalLen < uint16(hdrLen):
		err = errors.New("invalid ipv4 packet length")
		totalLen = 0
	case len(b) < int(totalLen):
		err = ErrShortBuffer
	}

	return int(totalLen), err
}

func IPv6TotalLen(b []byte) (int, error) {

	if len(b) < FixIPv6HdrLen {
		return 0, ErrShortBuffer
	}

	totalLen := FixIPv6HdrLen + int(be16(b[4:6]))
	if len(b) < totalLen {
		return totalLen, ErrShortBuffer
	}

	if totalLen > int(^uint16(0)) {
		return 0, errors.New("invalid ipv6 packet length")
	}

	return totalLen, nil
}
