//go:build netbsd || openbsd

package subpass

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

const tunCharPathFormat = "/dev/tun%d"
const tunOpenMode = unix.O_CLOEXEC | unix.O_RDWR

const tunIDMaxChar = 1 << 12
const tunMkNodMode = uint32(0600) | unix.S_IFCHR

func openTunFromCharDev(ifIndex int) (fd int, err error) {

	if ifIndex != -1 {
		return createIndexedTun(ifIndex)
	}

	var tunNodePath string
	for ifIndex = range tunIDMaxChar {
		tunNodePath = fmt.Sprintf(tunCharPathFormat, ifIndex)
		fd, err = unix.Open(tunNodePath, tunOpenMode, 0)
		if err == nil || !errors.Is(err, unix.EBUSY) {
			break
		}
	}

	if !errors.Is(err, os.ErrNotExist) {
		return fd, fmt.Errorf("open %s: %w", tunNodePath, err)
	}

	if err = createTunNode(ifIndex); err != nil {
		return fd, err
	}

	fd, err = unix.Open(tunNodePath, tunOpenMode, 0)
	if err != nil {
		return fd, fmt.Errorf("open %s: %w", tunNodePath, err)
	}

	return
}

func createIndexedTun(ifIndex int) (fd int, err error) {

	fullPath := fmt.Sprintf(tunCharPathFormat, ifIndex)

	fd, err = unix.Open(fullPath, tunOpenMode, 0)
	if err == nil {
		return fd, nil
	}

	if !errors.Is(err, os.ErrNotExist) {
		return fd, fmt.Errorf("open %s: %w", fullPath, err)
	}

	if err = createTunNode(ifIndex); err != nil {
		return fd, err
	}

	fd, err = unix.Open(fullPath, tunOpenMode, 0)
	if err != nil {
		return fd, fmt.Errorf("open %s: %w", fullPath, err)
	}

	return
}

func createTunNode(ifIndex int) error {
	nodePath := fmt.Sprintf(tunCharPathFormat, ifIndex)
	zeroNode := fmt.Sprintf(tunCharPathFormat, 0)

	stat, err := os.Stat(zeroNode)
	if err != nil {
		return err
	}

	minor := uint32(ifIndex)
	major := unix.Major(uint64(stat.Sys().(*syscall.Stat_t).Rdev))

	deviceRdev := unix.Mkdev(major, minor)

	err = unix.Mknod(nodePath, tunMkNodMode, int(deviceRdev))
	if err != nil {
		err = fmt.Errorf("mknod %s: %w", nodePath, err)
	}
	return err
}
