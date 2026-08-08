//go:build linux

package subpass

import (
	"errors"
	"fmt"
	"math"
	"os"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

const tunModuleCharPath = "/dev/net/tun"
const tunOpenMode = unix.O_CLOEXEC | unix.O_RDWR

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
	ifIndex    uint64
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

	flags := uint16(unix.IFF_NO_PI | unix.IFF_TUN)
	if config.MultiQueue {
		flags |= unix.IFF_MULTI_QUEUE
	}

	ifreq.SetUint16(flags)

	if err = unix.IoctlIfreq(fd, unix.TUNSETIFF, ifreq); err != nil {
		return tun, fmt.Errorf("failed to create tunnel: %w", err)
	}

	var value int
	if config.Persist {
		value++
	}

	err = unix.IoctlSetInt(fd, unix.TUNSETPERSIST, value)
	if err != nil {
		return tun, fmt.Errorf("failed to make tun persist: %w", err)
	}

	tunName := ifreq.Name()

	defer func() {
		if err != nil && value > 0 {
			destroyByName(tunName)
		}
	}()

	if err = tunDevicePermisstions(fd, config); err != nil {
		return
	}

	inet, err := unix.Socket(unix.AF_INET,
		unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return tun, fmt.Errorf("failed to open socket: %w", err)
	}

	defer unix.Close(inet)

	err = unix.IoctlIfreq(inet, unix.SIOCGIFINDEX, ifreq)
	if err != nil {
		return tun, fmt.Errorf("failed to get interface index: %w", err)
	}

	if err = unix.SetNonblock(fd, true); err != nil {
		return tun, fmt.Errorf("failed to set nonblock mode: %w", err)
	}

	tun = &tunDevice{}
	tun.ifIndex = uint64(ifreq.Uint32())
	tun.file = os.NewFile(uintptr(fd), tunModuleCharPath)
	return
}

func (tun *tunDevice) Name() (name string, err error) {

	sysconn, err := tun.file.SyscallConn()
	if err != nil {
		return name, fmt.Errorf(
			"name: unable to get tun name: %w", err)
	}

	var ifreq unix.Ifreq
	var opErr error
	err = sysconn.Control(func(fd uintptr) {
		opErr = unix.IoctlIfreq(int(fd), unix.TUNGETIFF, &ifreq)
	})

	if err != nil {
		return name, fmt.Errorf(
			"name: unable to get tun name: %w", err)
	}

	if opErr != nil {
		return name, fmt.Errorf(
			"name: unable to get tun name: %w", opErr)
	}

	return ifreq.Name(), nil
}

func (tun *tunDevice) Destroy() error {
	if err := Destroy(tun.ifIndex); err != nil {
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
		return 0, fmt.Errorf("read: invalid read of ip packet")
	}

	_, totalLen, err := checkPacketLen(b[:n])
	if err != nil {
		return 0, fmt.Errorf("read: %w", err)
	}

	if totalLen != n {
		return 0, fmt.Errorf("read: invalid read of ip packet")
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

func (tun *tunDevice) ID() uint64 { return tun.ifIndex }

func Destroy(ifindex uint64) error {

	if ifindex == 0 || ifindex > math.MaxInt32 {
		return fmt.Errorf("invalid interface index: %d", ifindex)
	}

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("open netlink socket: %w", err)
	}
	defer unix.Close(fd)

	lsa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Bind(fd, lsa); err != nil {
		return fmt.Errorf("bind netlink socket: %w", err)
	}

	nlmsgLen := unix.SizeofNlMsghdr + unix.SizeofIfInfomsg
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
		Index:  int32(ifindex),
	}
	*(*unix.IfInfomsg)(unsafe.Pointer(&buff[offset])) = ifinfo

	if err := unix.Sendto(fd, buff, 0, lsa); err != nil {
		return fmt.Errorf("send netlink delete request: %w", err)
	}

	rb := make([]byte, 4096)
	n, _, err := unix.Recvfrom(fd, rb, 0)
	if err != nil {
		return fmt.Errorf("receive netlink reply: %w", err)
	}

	if n < unix.SizeofNlMsghdr {
		return fmt.Errorf("receive netlink reply: short read header")
	}

	replyHeader := (*unix.NlMsghdr)(unsafe.Pointer(&rb[0]))
	if replyHeader.Type != unix.NLMSG_ERROR {
		return nil
	}

	if n < unix.SizeofNlMsghdr+unix.SizeofNlMsgerr {
		return fmt.Errorf("receive netlink reply: short read error message")
	}

	nlerr := (*unix.NlMsgerr)(unsafe.Pointer(&rb[unix.SizeofNlMsghdr]))
	if nlerr.Error != 0 {
		err = unix.Errno(-nlerr.Error)
		err = fmt.Errorf("netlink rejected deletion: %w", err)
	}

	return err
}

func tunDevicePermisstions(fd int, config *Config) (err error) {
	if config.Permissions == nil {
		return
	}

	owner := config.Permissions.Owner
	group := config.Permissions.Group

	err = unix.IoctlSetInt(fd, unix.TUNSETOWNER, int(owner))
	if err != nil {
		return fmt.Errorf("unable to set tunnel owner: %w", err)
	}

	err = unix.IoctlSetInt(fd, unix.TUNSETGROUP, int(group))
	if err != nil {
		return fmt.Errorf("unable to set tunnel group: %w", err)
	}

	return
}

func destroyByName(name string) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("open netlink socket: %w", err)
	}
	defer unix.Close(fd)

	lsa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Bind(fd, lsa); err != nil {
		return fmt.Errorf("bind netlink socket: %w", err)
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
		return fmt.Errorf("receive netlink reply: short read header")
	}

	replyHeader := (*unix.NlMsghdr)(unsafe.Pointer(&rb[0]))
	if replyHeader.Type != unix.NLMSG_ERROR {
		return nil
	}

	if n < unix.SizeofNlMsghdr+unix.SizeofNlMsgerr {
		return fmt.Errorf("receive netlink reply: short read error message")
	}

	nlerr := (*unix.NlMsgerr)(unsafe.Pointer(&rb[unix.SizeofNlMsghdr]))
	if nlerr.Error != 0 {
		err = unix.Errno(-nlerr.Error)
		err = fmt.Errorf("netlink rejected deletion: %w", err)
	}

	return err
}
