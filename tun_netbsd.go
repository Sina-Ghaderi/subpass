//go:build netbsd

package subpass

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

type Config struct {
	Name    string
	PTPMode bool
}

type tunDevice struct {
	file       *os.File
	readMutex  sync.Mutex
	writeMutex sync.Mutex
	closed     atomic.Bool
	name       string
}

type Tun interface {
	io.ReadWriteCloser
	Name() string
	Destroy() error
}

func defaltOSparms() Config { return Config{} }

func openTunDevice(config *Config) (*tunDevice, error) {

	dev, err := createTunDevice(config)
	if err == nil {
		return dev, err
	}

	err = fmt.Errorf("open device: %w", err)
	if dev != nil && dev.file != nil {
		dev.file.Close()
	}

	dev = nil
	return dev, err
}

func createTunDevice(config *Config) (tun *tunDevice, err error) {
	index, err := getTunIndex(config)
	if err != nil {
		return tun, err
	}

	tun = new(tunDevice)
	fd, err := openTunFromCharDev(index)
	if err != nil {
		return tun, err
	}

	defer func() {
		if err != nil {
			unix.Close(fd)
		}
	}()

	var stat_t unix.Stat_t

	if err = unix.Fstat(fd, &stat_t); err != nil {
		return tun, fmt.Errorf("get tunnel name: %w", err)
	}

	if err = unix.SetNonblock(fd, true); err != nil {
		return tun, fmt.Errorf("set nonblock: %w", err)
	}

	tun.name = fmt.Sprintf("tun%d", unix.Minor(uint64(stat_t.Rdev)))
	tun.file = os.NewFile(uintptr(fd), tun.name)

	defer func() {
		if err != nil {
			Destroy(tun.name)
		}
	}()

	err = setTunIFHeadMode(tun.file)
	if err != nil {
		return tun, fmt.Errorf("set ifhead mode: %w", err)
	}

	if config.PTPMode {
		return
	}

	err = setTunBroadcastMode(tun.file)
	if err != nil {
		return tun, fmt.Errorf("set broadcast mode: %w", err)
	}

	return
}

func (iface *tunDevice) Close() error {
	if iface.closed.Swap(true) {
		return fmt.Errorf("close: %w", os.ErrClosed)
	}

	var err error
	if iface.file != nil {
		err = iface.file.Close()
	}
	if err != nil {
		return fmt.Errorf("close: %w", err)
	}
	return err
}

func setTunBroadcastMode(f *os.File) error {
	sysconn, err := f.SyscallConn()
	if err != nil {
		return err
	}

	var errno syscall.Errno

	err = sysconn.Control(func(fd uintptr) {
		const TUNSIFMODE = 0x80047458
		ifFlags := unix.IFF_BROADCAST | unix.IFF_MULTICAST
		_, _, errno = unix.Syscall(
			unix.SYS_IOCTL,
			fd,
			uintptr(TUNSIFMODE),
			uintptr(unsafe.Pointer(&ifFlags)),
		)
	})

	if err != nil {
		return err
	}

	if errno != 0 {
		return errno
	}

	return nil
}

func setTunIFHeadMode(f *os.File) error {
	sysconn, err := f.SyscallConn()
	if err != nil {
		return err
	}

	var errno syscall.Errno

	err = sysconn.Control(func(fd uintptr) {
		const TUNSIFHEAD = 0x80047442
		ifheadmode := 1
		_, _, errno = unix.Syscall(
			unix.SYS_IOCTL,
			fd,
			TUNSIFHEAD,
			uintptr(unsafe.Pointer(&ifheadmode)),
		)
	})

	if err != nil {
		return err
	}

	if errno != 0 {
		return errno
	}

	return nil
}

func getTunIndex(config *Config) (int, error) {
	ifIndex := -1
	if len(config.Name) == 0 {
		return ifIndex, nil
	}

	const tunPrefix = "tun"
	if !strings.HasPrefix(config.Name, tunPrefix) {
		return ifIndex, errors.New("interface name must be tun[0-9]+")
	}
	ifIndex, err := strconv.Atoi(config.Name[len(tunPrefix):])
	if err != nil || ifIndex < 0 {
		return ifIndex, errors.New("interface name must be tun[0-9]+")
	}

	if len(config.Name) >= unix.IFNAMSIZ {
		return ifIndex, errors.New("interface name too long")
	}

	return ifIndex, nil
}

func (tun *tunDevice) Destroy() error {
	if err := Destroy(tun.name); err != nil {
		return fmt.Errorf("destroy: %w", err)
	}
	return nil
}

func (tun *tunDevice) Name() string { return tun.name }

func Destroy(name string) error {

	const sockType = unix.SOCK_DGRAM | unix.SOCK_CLOEXEC

	fd, err := unix.Socket(unix.AF_INET, sockType, 0)
	if err != nil {
		return fmt.Errorf("open socket: %w", err)
	}

	defer unix.Close(fd)

	var ifr [32]byte
	copy(ifr[:], name)
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCIFDESTROY),
		uintptr(unsafe.Pointer(&ifr[0])),
	)
	if errno != 0 {
		return fmt.Errorf("interface destroy request: %w", errno)
	}

	return nil
}
