//go:build darwin

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

	"golang.org/x/sys/unix"
)

const appleUtunCtl = "com.apple.net.utun_control"
const appleSYSPROTO_CONTROL = 2

type Config struct {
	Name string
}

type tunDevice struct {
	readMutex  sync.Mutex
	writeMutex sync.Mutex
	closed     atomic.Bool
	ifIndex    uint64
	file       *os.File
}

func defaltOSparms() Config { return Config{} }

func socketCloexec(family, sotype, proto int) (fd int, err error) {
	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()

	fd, err = unix.Socket(family, sotype, proto)
	if err == nil {
		unix.CloseOnExec(fd)
	}
	return
}

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

	index, err := getUtunIndex(config)
	if err != nil {
		return tun, err
	}

	fd, err := socketCloexec(
		unix.AF_SYSTEM, unix.SOCK_DGRAM, appleSYSPROTO_CONTROL)
	if err != nil {
		return tun, fmt.Errorf("failed to open socket: %w", err)
	}

	var ctlInfo = new(unix.CtlInfo)
	copy(ctlInfo.Name[:], []byte(appleUtunCtl))

	if err = unix.IoctlCtlInfo(fd, ctlInfo); err != nil {
		unix.Close(fd)
		return tun, fmt.Errorf("failed to create tunnel: %w", err)
	}

	control := &unix.SockaddrCtl{ID: ctlInfo.Id}
	control.Unit = uint32(index) + 1

	if err = unix.Connect(fd, control); err != nil {
		unix.Close(fd)
		return tun, fmt.Errorf("failed to connect to socket: %w", err)
	}

	const UTUN_OPT_IFNAME = 2
	utunName, err := unix.GetsockoptString(
		fd, appleSYSPROTO_CONTROL, UTUN_OPT_IFNAME,
	)

	if err != nil {
		unix.Close(fd)
		return tun, fmt.Errorf("unable to get tunnel name: %w", err)
	}

	iface, err := net.InterfaceByName(utunName)
	if err != nil {
		unix.Close(fd)
		return tun, fmt.Errorf("failed to get interface index: %w", err)
	}

	if err = unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return tun, fmt.Errorf("failed to put in nonblock: %w", err)
	}

	tun = new(tunDevice)
	tun.ifIndex = uint64(iface.Index)
	tun.file = os.NewFile(uintptr(fd), utunName)
	return
}

func (tun *tunDevice) ID() uint64 { return tun.ifIndex }

func (tun *tunDevice) Name() (name string, err error) {

	sysconn, err := tun.file.SyscallConn()
	if err != nil {
		return name, fmt.Errorf(
			"name: failed to get tun name: %w", err)
	}

	var opErr error

	err = sysconn.Control(func(fd uintptr) {
		const UTUN_OPT_IFNAME = 2
		name, opErr = unix.GetsockoptString(
			int(fd), appleSYSPROTO_CONTROL, UTUN_OPT_IFNAME,
		)
	})

	if err != nil {
		return name, fmt.Errorf(
			"name: failed to get tun name: %w", err)
	}

	if opErr != nil {
		return name, fmt.Errorf(
			"name: failed to get tun name: %w", opErr)
	}

	return name, err
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

func getUtunIndex(config *Config) (int, error) {
	ifIndex := -1
	if len(config.Name) == 0 {
		return ifIndex, nil
	}

	const utunPrefix = "utun"
	if !strings.HasPrefix(config.Name, utunPrefix) {
		return ifIndex, errors.New("interface name must be utun[0-9]+")
	}
	ifIndex, err := strconv.Atoi(config.Name[len(utunPrefix):])
	if err != nil || ifIndex < 0 {
		return ifIndex, errors.New("interface name must be utun[0-9]+")
	}

	if ifIndex > math.MaxUint32-1 {
		return ifIndex, errors.New("interface name too long")
	}

	return ifIndex, nil
}

func (tun *tunDevice) Destroy() error {
	return errors.New("destroy: operation not supported on this platform")
}
