//go:build linux

package subpass

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"github.com/sina-ghaderi/tcpip"
	"golang.org/x/sys/unix"

	"github.com/sina-ghaderi/virtio/net"
	"github.com/sina-ghaderi/virtio/offloads"
)

const tcpOffloads = unix.TUN_F_CSUM | unix.TUN_F_TSO4 | unix.TUN_F_TSO6
const udpOffloads = unix.TUN_F_USO4 | unix.TUN_F_USO6

type tunDeviceOffload struct {
	readMutex  sync.Mutex
	writeMutex sync.Mutex
	file       *os.File
	gso        *offloads.VirtioGso
	gro        *offloads.VirtioGro
	closed     atomic.Bool
	name       string
}

func openOffloadTun(config *Config) (*tunDeviceOffload, error) {
	dev, err := createTunOffload(config)
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

func createTunOffload(config *Config) (tun *tunDeviceOffload, err error) {

	if config.EnableOffloads && config.UseVHostNet {
		return nil, fmt.Errorf("offloads cannot be used with vhost-net")
	}

	if err = validateName(config.Name); err != nil {
		return
	}

	fd, err := unix.Open(tunModuleCharPath, tunOpenMode, 0)
	if err != nil {
		return tun, fmt.Errorf("open %s: %w", tunModuleCharPath, err)
	}

	defer func() {
		if err != nil {
			unix.Close(fd)
		}
	}()

	ifreq, err := unix.NewIfreq(config.Name)
	if err != nil {
		return tun, errors.New("interface name too long")
	}

	flags := uint16(unix.IFF_NO_PI | unix.IFF_TUN | unix.IFF_TUN_EXCL |
		unix.IFF_VNET_HDR)
	if config.MultiQueue {
		flags |= unix.IFF_MULTI_QUEUE
	}

	ifreq.SetUint16(flags)

	if err = unix.IoctlIfreq(fd, unix.TUNSETIFF, ifreq); err != nil {
		if errors.Is(err, unix.EBUSY) {
			err = os.ErrExist
		}
		return tun, fmt.Errorf("create tunnel: %w", err)
	}

	var value int
	if config.Persist {
		value++
	}

	err = unix.IoctlSetInt(fd, unix.TUNSETPERSIST, value)
	if err != nil {
		return tun, fmt.Errorf("set persist mode: %w", err)
	}

	tunName := ifreq.Name()

	defer func() {
		if err != nil && value > 0 {
			Destroy(tunName)
		}
	}()

	if err = tunDevicePermisstions(fd, config); err != nil {
		return
	}

	if err = unix.SetNonblock(fd, true); err != nil {
		return tun, fmt.Errorf("set nonblock: %w", err)
	}

	tun = &tunDeviceOffload{name: tunName}
	tun.file = os.NewFile(uintptr(fd), tunName)

	if err = setTunNetHdrSize(tun.file); err != nil {
		return tun, fmt.Errorf("set nethdr size: %w", err)
	}

	var udp bool

	udp, err = setTunOffloads(tun.file)
	if err != nil {
		return tun, fmt.Errorf("set offloads: %w", err)
	}

	tun.gso = offloads.NewVirtioGso()
	tun.gro = offloads.NewVirtioGro(udp)
	return
}

func (tun *tunDeviceOffload) Name() string {
	return tun.name
}

func (tun *tunDeviceOffload) Destroy() error {
	if err := Destroy(tun.name); err != nil {
		return fmt.Errorf("destroy: %w", err)
	}
	return nil
}

func (tun *tunDeviceOffload) Read(b []byte) (int, error) {

	if tun.closed.Load() {
		return 0, fmt.Errorf("read: %w", os.ErrClosed)
	}

	tun.readMutex.Lock()
	defer tun.readMutex.Unlock()

	n, err := tun.gso.Recv(tun.file, b)
	switch err {
	case nil:
	case tcpip.ErrShortBuffer:
		return 0, fmt.Errorf("read: %w", ErrShortBuffer)
	default:
		return 0, fmt.Errorf("read: %w", err)
	}

	return n, err
}

func (tun *tunDeviceOffload) Write(b []byte) (int, error) {

	if tun.closed.Load() {
		return 0, fmt.Errorf("write: %w", os.ErrClosed)
	}

	tun.writeMutex.Lock()
	defer tun.writeMutex.Unlock()

	n, err := tun.gro.Send(tun.file, b)
	switch err {
	case nil:
	case tcpip.ErrShortBuffer:
		return 0, fmt.Errorf("write: %w", ErrShortBuffer)
	default:
		return 0, fmt.Errorf("write: %w", err)
	}

	return n, err
}

func (tun *tunDeviceOffload) Close() error {

	if tun.closed.Swap(true) {
		return fmt.Errorf("close: %w", os.ErrClosed)
	}

	var err error
	if tun.file != nil {
		err = tun.file.Close()
	}

	if err != nil {
		return fmt.Errorf("close: %w", err)
	}

	return err
}

func setTunNetHdrSize(file *os.File) error {

	sysconn, err := file.SyscallConn()
	if err != nil {
		return err
	}

	var opErr error
	err = sysconn.Control(func(fd uintptr) {
		opErr = unix.IoctlSetPointerInt(int(fd),
			unix.TUNSETVNETHDRSZ, net.VirtioNetHdrLen)
	})
	if err != nil {
		return err
	}

	if opErr != nil {
		return opErr
	}

	return nil
}

func setTunOffloads(file *os.File) (bool, error) {

	sysconn, err := file.SyscallConn()
	if err != nil {
		return false, err
	}

	var opErr error
	var ifreq unix.Ifreq
	var udpEnable bool

	err = sysconn.Control(func(fd uintptr) {
		opErr = unix.IoctlIfreq(int(fd), unix.TUNGETIFF, &ifreq)
		if opErr != nil {
			return
		}

		flags := ifreq.Uint16()
		if flags&unix.IFF_VNET_HDR == 0 {
			opErr = errors.New("kernel did not grant virtio nethdr")
			return
		}

		opErr = unix.IoctlSetInt(int(fd),
			unix.TUNSETOFFLOAD, tcpOffloads)
		if opErr != nil {
			return
		}

		udpErr := unix.IoctlSetInt(
			int(fd),
			unix.TUNSETOFFLOAD,
			tcpOffloads|udpOffloads,
		)

		udpEnable = udpErr == nil
	})

	if err != nil {
		return false, err
	}

	if opErr != nil {
		return false, opErr
	}

	return udpEnable, nil
}
