//go:build freebsd

package subpass

import (
	"errors"
	"fmt"
	"io"
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

type Tun interface {
	io.ReadWriteCloser
	Name() string
	Destroy() error
}

type tunDevice struct {
	file       *os.File
	readMutex  sync.Mutex
	writeMutex sync.Mutex
	closed     atomic.Bool
	name       string
}

type Config struct {
	Name    string
	Persist bool
	PTPMode bool
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

	if len(config.Name) >= unix.IFNAMSIZ {
		return tun, errors.New("interface name too long")
	}

	netif, err := net.InterfaceByName(config.Name)
	if netif != nil {
		return tun, fmt.Errorf("create tunnel: %w", os.ErrExist)
	}

	tun = new(tunDevice)
	fd, err := unix.Open(tunModuleCharPath, tunOpenMode, 0)
	if err != nil {
		return tun, fmt.Errorf("open %s: %w", tunModuleCharPath, err)
	}

	defer func() {
		if err != nil {
			unix.Close(fd)
		}
	}()

	var ifreq struct {
		name [unix.IFNAMSIZ]byte
		_    [16]byte
	}

	const TUNGIFNAME = 0x4020745d
	_, _, errno := unix.Syscall(unix.SYS_IOCTL,
		uintptr(fd), TUNGIFNAME,
		uintptr(unsafe.Pointer(&ifreq)),
	)

	if errno != 0 {
		err = fmt.Errorf("get tunnel name: %w", errno)
		return
	}

	tunName := unix.ByteSliceToString(ifreq.name[:])

	if !config.Persist {
		err = setTunTransient(fd)
		if err != nil {
			return tun, fmt.Errorf("set transient mode: %w", err)
		}
	} else {
		defer func() {
			if err != nil {
				Destroy(tunName)
			}
		}()
	}

	err = setTunIFHeadMode(fd)
	if err != nil {
		return tun, fmt.Errorf("set ifhead mode: %w", err)
	}

	if !config.PTPMode {
		err = setTunBroadcastMode(fd)
		if err != nil {
			return tun, fmt.Errorf("set broadcast mode: %w", err)
		}
	}

	err = becomeTunPID(fd)
	if err != nil {
		return tun, fmt.Errorf(
			"set controlling tunnel process: %w", err)
	}

	if len(config.Name) != 0 {
		err = setTunName(tunName, config.Name)
		if err != nil {
			return tun, fmt.Errorf("rename %s to %s: %w",
				tunName, config.Name, err,
			)
		}

		tunName = config.Name
	}

	tun.name = tunName

	if err = unix.SetNonblock(fd, true); err != nil {
		return tun, fmt.Errorf("set nonblock: %w", err)
	}

	tun.file = os.NewFile(uintptr(fd), tunName)
	return
}

func (tun *tunDevice) Name() string {
	return tun.name
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
	if err := Destroy(tun.name); err != nil {
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
	return err
}

func setTunTransient(fd int) error {

	var errno syscall.Errno
	const TUNSTRANSIENT = 0x80047462
	transient := 1
	_, _, errno = unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		TUNSTRANSIENT,
		uintptr(unsafe.Pointer(&transient)),
	)

	if errno != 0 {
		return errno
	}

	return nil
}

func setTunIFHeadMode(fd int) error {

	var errno syscall.Errno

	const TUNSIFHEAD = 0x80047460
	ifheadmode := 1
	_, _, errno = unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		TUNSIFHEAD,
		uintptr(unsafe.Pointer(&ifheadmode)),
	)

	if errno != 0 {
		return errno
	}

	return nil
}

func becomeTunPID(fd int) error {

	var errno syscall.Errno
	const TUNSIFPID = 0x2000745f
	_, _, errno = unix.Syscall(
		unix.SYS_IOCTL, uintptr(fd), TUNSIFPID, uintptr(0),
	)
	if errno != 0 {
		return errno
	}

	return nil
}

func setTunBroadcastMode(fd int) error {

	const TUNSIFMODE = 0x8004745e
	var errno syscall.Errno
	ifFlags := unix.IFF_BROADCAST | unix.IFF_MULTICAST
	_, _, errno = unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(TUNSIFMODE),
		uintptr(unsafe.Pointer(&ifFlags)),
	)

	if errno != 0 {
		return errno
	}

	return nil
}
