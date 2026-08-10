//go:build netbsd || openbsd || darwin || dragonfly || freebsd

package subpass

import (
	"fmt"
	"math"
	"os"

	"github.com/sina-ghaderi/subpass/tcpip"
	"golang.org/x/sys/unix"
)

const addrFamilyTagLen = 0x04
const maxPacketLen = math.MaxUint16 + addrFamilyTagLen

func (tun *tunDevice) Read(b []byte) (int, error) {

	if tun.closed.Load() {
		return 0, fmt.Errorf("read: %w", os.ErrClosed)
	}

	tun.readMutex.Lock()
	defer tun.readMutex.Unlock()

	buff := make([]byte, maxPacketLen)

	n, err := tun.file.Read(buff)
	if err != nil {
		return 0, fmt.Errorf("read: %w", err)
	}

	if n < addrFamilyTagLen {
		return 0, fmt.Errorf("read: short address family tag")
	}

	if n > len(buff) {
		return 0, fmt.Errorf("read: read: invalid ip packet length")
	}

	buff = buff[addrFamilyTagLen:n]
	if len(b) < len(buff) {
		return 0, fmt.Errorf("read: %w", ErrShortBuffer)
	}

	totalLen, err := tcpip.TotalLen(buff)
	if err != nil {
		if err == tcpip.ErrShortBuffer {
			return 0, fmt.Errorf("read: short ip packet")
		}
		return 0, fmt.Errorf("read: %w", err)
	}

	if totalLen != len(buff) {
		return 0, fmt.Errorf("read: invalid ip packet length")
	}

	return copy(b, buff), err
}

func (tun *tunDevice) Write(b []byte) (int, error) {

	if tun.closed.Load() {
		return 0, fmt.Errorf("write: %w", os.ErrClosed)
	}

	tun.writeMutex.Lock()
	defer tun.writeMutex.Unlock()

	buff := make([]byte, maxPacketLen)

	v, lb, err := checkPacketLen(b)
	if err != nil {
		return 0, fmt.Errorf("write: %w", err)
	}

	if v == tcpip.IPv4 {
		buff[3] = unix.AF_INET
	} else {
		buff[3] = unix.AF_INET6
	}

	cp := copy(buff[addrFamilyTagLen:], b[:lb])
	dataLen := cp + addrFamilyTagLen

	n, err := tun.file.Write(buff[:dataLen])
	if err != nil {
		return 0, fmt.Errorf("write: %w", err)
	}

	if n < addrFamilyTagLen {
		return 0, fmt.Errorf("write: short address family tag")
	}

	return cp, err
}
