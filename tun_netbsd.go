//go:build netbsd

package subpass

import (
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const tunCharPathFormat = "/dev/tun%d"
const tunOpenMode = unix.O_CLOEXEC | unix.O_RDWR

type Config struct {
	Name    string
	PTPMode bool
}

type tunDevice struct {
	file       *os.File
	readMutex  sync.Mutex
	writeMutex sync.Mutex
	closed     atomic.Bool
	ifIndex    uint64
	name       string
}

func defaltOSparms() Config { return Config{} }

func openTunDevice(config *Config) (*tunDevice, error) {

	dev, err := createTunDevice(config)
	if err == nil {
		return dev, err
	}

	err = fmt.Errorf("create device: %w", err)
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
	tun.file, err = openTunFromCharDev(index)
	if err != nil {
		return tun, err
	}

	stat, err := tun.file.Stat()
	if err != nil {
		return tun, fmt.Errorf("get tunnel name: %w", err)
	}

	stat_t := stat.Sys().(*syscall.Stat_t)
	tun.name = fmt.Sprintf("tun%d", unix.Minor(uint64(stat_t.Rdev)))

	defer func() {
		if err != nil {
			destroyByName(tun.name)
		}
	}()

	iface, err := net.InterfaceByName(tun.name)
	if err != nil {
		return tun, fmt.Errorf("get interface index: %w", err)
	}

	tun.ifIndex = uint64(iface.Index)

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

func Destroy(ifindex uint64) error {

	if ifindex == 0 || ifindex > math.MaxInt32 {
		return fmt.Errorf("invalid interface index: %d", ifindex)
	}

	ifi, err := net.InterfaceByIndex(int(ifindex))
	if err != nil {
		return fmt.Errorf("get interface index: %w", err)
	}

	name := ifi.Name
	return destroyByName(name)

}

func (tun *tunDevice) Destroy() error {
	if err := Destroy(tun.ifIndex); err != nil {
		return fmt.Errorf("destroy: %w", err)
	}
	return nil
}

func (tun *tunDevice) ID() uint64              { return tun.ifIndex }
func (iface *tunDevice) Name() (string, error) { return iface.name, nil }

func destroyByName(name string) error {

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
