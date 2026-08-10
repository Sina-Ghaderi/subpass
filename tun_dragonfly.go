//go:build dragonfly

package subpass

import (
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const tunModuleCharPath = "/dev/tun"
const tunOpenMode = unix.O_CLOEXEC | unix.O_RDWR

type tunDevice struct {
	file       *os.File
	readMutex  sync.Mutex
	writeMutex sync.Mutex
	closed     atomic.Bool
	ifIndex    uint64
}

type Config struct {
	Name    string
	PTPMode bool
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

	if len(config.Name) >= unix.IFNAMSIZ {
		return tun, errors.New("interface name too long")
	}

	netif, err := net.InterfaceByName(config.Name)
	if netif != nil {
		return tun, fmt.Errorf("create tunnel: %w", os.ErrExist)
	}

	tun = new(tunDevice)
	tun.file, err = os.OpenFile(tunModuleCharPath, tunOpenMode, 0)
	if err != nil {
		return tun, err
	}

	tunName, err := getTunName(tun.file)
	if err != nil {
		return tun, fmt.Errorf("get tunnel name: %w", err)
	}

	defer func() {
		if err != nil {
			destroyByName(tunName)
		}
	}()

	err = setTunIFHeadMode(tun.file)
	if err != nil {
		return tun, fmt.Errorf("set ifhead mode: %w", err)
	}

	if !config.PTPMode {
		err = setTunBroadcastMode(tun.file)
		if err != nil {
			return tun, fmt.Errorf("set broadcast mode: %w", err)
		}
	}

	err = becomeTunPID(tun.file)
	if err != nil {
		return tun, fmt.Errorf(
			"set controlling tunnel process: %w", err)
	}

	netif, err = net.InterfaceByName(tunName)
	if err != nil {
		return tun, fmt.Errorf("get interface index: %w", err)
	}

	tun.ifIndex = uint64(netif.Index)

	if len(config.Name) == 0 {
		return
	}

	err = setTunName(tunName, config.Name)
	if err != nil {
		return tun, fmt.Errorf("rename %s to %s: %w",
			tunName, config.Name, err,
		)
	}

	return
}

func (tun *tunDevice) Name() (string, error) {
	name, err := getTunName(tun.file)
	if err != nil {
		return name, fmt.Errorf("name: get tunnel name: %w", err)
	}

	return name, err
}

func setTunName(oldName, newName string) error {

	confd, err := unix.Socket(
		unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0,
	)
	if err != nil {
		return fmt.Errorf("open socket: %w", err)
	}

	defer unix.Close(confd)

	var nameData [unix.IFNAMSIZ]byte
	var ifr struct {
		Name [unix.IFNAMSIZ]byte
		Data uintptr
		_    [16 - unsafe.Sizeof(uintptr(0))]byte
	}

	copy(nameData[:], newName)
	copy(ifr.Name[:], oldName)

	ifr.Data = uintptr(unsafe.Pointer(&nameData[0]))
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(confd),
		uintptr(unix.SIOCSIFNAME),
		uintptr(unsafe.Pointer(&ifr)),
	)

	if errno != 0 {
		return errno
	}

	return nil
}

func (tun *tunDevice) Destroy() error {
	if err := Destroy(tun.ifIndex); err != nil {
		return fmt.Errorf("destroy: %w", err)
	}
	return nil
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
		err = fmt.Errorf("close: %w", err)
	}

	return err
}

func (tun *tunDevice) ID() uint64 { return tun.ifIndex }

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
	return err
}

func getTunName(f *os.File) (name string, err error) {
	sysconn, err := f.SyscallConn()
	if err != nil {
		return name, err
	}

	var errno syscall.Errno

	var ifreq struct {
		name [unix.IFNAMSIZ]byte
		_    [16]byte
	}

	err = sysconn.Control(func(fd uintptr) {
		const TUNGIFNAME = 0x40207462
		_, _, errno = unix.Syscall(
			unix.SYS_IOCTL, fd, TUNGIFNAME,
			uintptr(unsafe.Pointer(&ifreq)),
		)
	})

	if err != nil {
		return name, err
	}

	if errno != 0 {
		return name, errno
	}

	name = unix.ByteSliceToString(ifreq.name[:])
	return
}

func setTunIFHeadMode(f *os.File) error {
	sysconn, err := f.SyscallConn()
	if err != nil {
		return err
	}

	var errno syscall.Errno

	err = sysconn.Control(func(fd uintptr) {
		const TUNSIFHEAD = 0x80047460
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

func becomeTunPID(f *os.File) error {
	sysconn, err := f.SyscallConn()
	if err != nil {
		return err
	}

	var errno syscall.Errno

	err = sysconn.Control(func(fd uintptr) {
		const TUNSIFPID = 0x2000745f
		_, _, errno = unix.Syscall(
			unix.SYS_IOCTL, fd, TUNSIFPID, uintptr(0),
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

func setTunBroadcastMode(f *os.File) error {
	sysconn, err := f.SyscallConn()
	if err != nil {
		return err
	}

	var errno syscall.Errno

	err = sysconn.Control(func(fd uintptr) {
		const TUNSIFMODE = 0x8004745e

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
