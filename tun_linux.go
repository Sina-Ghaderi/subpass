//go:build linux

package subpass

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

const tunModuleCharPath = "/dev/net/tun"
const tunOpenMode = unix.O_CLOEXEC | unix.O_RDWR

type Tun interface {
	io.ReadWriteCloser
	Name() string
	Destroy() error
}

type Config struct {
	Name           string
	Permissions    *Permissions
	Persist        bool
	MultiQueue     bool
	EnableOffloads bool
	UseVhostNet    bool
}

type Permissions struct {
	Owner uint
	Group uint
}

type tunDevice struct {
	readMutex  sync.Mutex
	writeMutex sync.Mutex
	file       *os.File
	closed     atomic.Bool
	name       string
}

func defaltOSparms() Config { return Config{} }

var validIfaceRegex = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)

func openTunDevice(config *Config) (Tun, error) {

	switch {
	case config.EnableOffloads:
		return openOffloadTun(config)
	case config.UseVhostNet:
		// TODO:
	}

	return openGenericTun(config)
}

func openGenericTun(config *Config) (*tunDevice, error) {

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

	flags := uint16(unix.IFF_NO_PI | unix.IFF_TUN | unix.IFF_TUN_EXCL)
	if config.MultiQueue {
		flags |= unix.IFF_MULTI_QUEUE
	}

	ifreq.SetUint16(flags)

	if err = unix.IoctlIfreq(fd, unix.TUNSETIFF, ifreq); err != nil {
		return tun, fmt.Errorf("create tunnel: %w", err)
	}

	tunName := ifreq.Name()

	var value int
	if config.Persist {
		value++
	}

	err = unix.IoctlSetInt(fd, unix.TUNSETPERSIST, value)
	if err != nil {
		return tun, fmt.Errorf("set persist mode: %w", err)
	}

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

	tun = &tunDevice{}
	tun.file = os.NewFile(uintptr(fd), tunName)
	tun.name = tunName
	return
}

func (tun *tunDevice) Name() (name string) { return tun.name }

func (tun *tunDevice) Destroy() error {
	if err := Destroy(tun.name); err != nil {
		return fmt.Errorf("destroy: %w", err)
	}
	return nil
}

func (tun *tunDevice) Close() error {

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

func (tun *tunDevice) Read(b []byte) (int, error) {

	if tun.closed.Load() {
		return 0, fmt.Errorf("read: %w", os.ErrClosed)
	}

	tun.readMutex.Lock()
	defer tun.readMutex.Unlock()

	n, err := tun.file.Read(b)
	if err != nil {
		return 0, fmt.Errorf("read: %w", err)
	}

	if n > len(b) {
		return 0, fmt.Errorf("read: invalid ip packet length")
	}

	_, totalLen, err := checkPacketLen(b[:n])
	if err != nil {
		return 0, fmt.Errorf("read: %w", err)
	}

	if totalLen != n {
		return 0, fmt.Errorf("read: invalid ip packet length")
	}

	return n, err
}

func (tun *tunDevice) Write(b []byte) (int, error) {

	if tun.closed.Load() {
		return 0, fmt.Errorf("write: %w", os.ErrClosed)
	}

	tun.writeMutex.Lock()
	defer tun.writeMutex.Unlock()

	_, plen, err := checkPacketLen(b)
	if err != nil {
		return 0, fmt.Errorf("write: %w", err)
	}

	n, err := tun.file.Write(b[:plen])
	if err != nil {
		return 0, fmt.Errorf("write: %w", err)
	}

	return n, err
}

func tunDevicePermisstions(fd int, config *Config) (err error) {
	if config.Permissions == nil {
		return
	}

	owner := config.Permissions.Owner
	group := config.Permissions.Group

	err = unix.IoctlSetInt(fd, unix.TUNSETOWNER, int(owner))
	if err != nil {
		return fmt.Errorf("set tunnel owner: %w", err)
	}

	err = unix.IoctlSetInt(fd, unix.TUNSETGROUP, int(group))
	if err != nil {
		return fmt.Errorf("set tunnel group: %w", err)
	}

	return
}

func Destroy(name string) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("open socket: %w", err)
	}
	defer unix.Close(fd)

	lsa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Bind(fd, lsa); err != nil {
		return fmt.Errorf("bind socket: %w", err)
	}

	nameBytes := append([]byte(name), 0)
	attrLen := 4 + len(nameBytes)
	attrAlignedLen := (attrLen + 3) &^ 3

	nlmsgLen := unix.SizeofNlMsghdr + unix.SizeofIfInfomsg + attrAlignedLen
	buff := make([]byte, nlmsgLen)

	nlmsg := unix.NlMsghdr{
		Len:   uint32(nlmsgLen),
		Type:  unix.RTM_DELLINK,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK,
		Seq:   1,
	}
	*(*unix.NlMsghdr)(unsafe.Pointer(&buff[0])) = nlmsg
	offset := unix.SizeofNlMsghdr

	ifinfo := unix.IfInfomsg{
		Family: unix.AF_UNSPEC,
	}
	*(*unix.IfInfomsg)(unsafe.Pointer(&buff[offset])) = ifinfo
	offset += unix.SizeofIfInfomsg

	rtAttr := unix.RtAttr{
		Len:  uint16(attrLen),
		Type: unix.IFLA_IFNAME,
	}
	*(*unix.RtAttr)(unsafe.Pointer(&buff[offset])) = rtAttr

	copy(buff[offset+4:], nameBytes)
	if err := unix.Sendto(fd, buff, 0, lsa); err != nil {
		return fmt.Errorf("send netlink delete request: %w", err)
	}

	rb := make([]byte, 4096)
	n, _, err := unix.Recvfrom(fd, rb, 0)
	if err != nil {
		return fmt.Errorf("receive netlink reply: %w", err)
	}

	if n < unix.SizeofNlMsghdr {
		return fmt.Errorf("receive netlink reply: short header")
	}

	replyHeader := (*unix.NlMsghdr)(unsafe.Pointer(&rb[0]))
	if replyHeader.Type != unix.NLMSG_ERROR {
		return nil
	}

	if n < unix.SizeofNlMsghdr+unix.SizeofNlMsgerr {
		return fmt.Errorf("receive netlink reply: short error message")
	}

	nlerr := (*unix.NlMsgerr)(unsafe.Pointer(&rb[unix.SizeofNlMsghdr]))
	if nlerr.Error != 0 {
		err = unix.Errno(-nlerr.Error)
		err = fmt.Errorf("netlink reject deletion: %w", err)
	}

	return err
}

func validateName(name string) error {
	if len(name) == 0 {
		return nil
	}

	if name == "." || name == ".." {
		return errors.New("invalid interface name")
	}

	if !validIfaceRegex.MatchString(name) {
		return errors.New("invalid interface name")
	}

	return nil
}
