//go:build solaris || illumos

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
	"unsafe"

	"github.com/sina-ghaderi/subpass/tcpip"
	"golang.org/x/sys/unix"
)

const tunModuleCharPath = "/dev/tun"
const ipModulePath = "/dev/ip"
const tunOpenMode = unix.O_CLOEXEC | unix.O_RDWR
const tunReadBufferLen = 1 << 16

type Tun interface {
	io.ReadWriteCloser
	Name() string
	Destroy() error
}

type tunDevice struct {
	readMutex  sync.Mutex
	writeMutex sync.Mutex
	name       string
	dataFile   *os.File
	linkFile   *os.File
	buff       []byte
	unread     []byte
	closed     atomic.Bool
}

type Config struct {
	Name    string
	Persist bool
}

func defaltOSparms() Config { return Config{} }

func openTunDevice(config *Config) (*tunDevice, error) {

	dev, err := createTunDevice(config)
	if err == nil {
		return dev, err
	}

	err = fmt.Errorf("open device: %w", err)
	if dev != nil {
		dev.Close()
	}

	dev = nil
	return dev, err

}

func createTunDevice(config *Config) (tun *tunDevice, err error) {

	ppa, err := getTunIndex(config.Name)
	if err != nil {
		return tun, err
	}

	ipFd, err := unix.Open(ipModulePath, tunOpenMode, 0)
	if err != nil {
		return tun, fmt.Errorf("open %s: %w", ipModulePath, err)
	}

	defer unix.Close(ipFd)

	tun = new(tunDevice)
	dataFd, err := unix.Open(tunModuleCharPath, tunOpenMode, 0)
	if err != nil {
		return tun, fmt.Errorf("open %s: %w", tunModuleCharPath, err)
	}

	defer func() {
		if err != nil {
			unix.Close(dataFd)
		}
	}()

	skppa, err := tunNewPPA(dataFd, ppa)
	if err != nil {
		return tun, fmt.Errorf("create tunnel: %w", err)
	}

	tunName := fmt.Sprintf("tun%d", skppa)

	linkFd, err := unix.Open(tunModuleCharPath, tunOpenMode, 0)
	if err != nil {
		return tun, fmt.Errorf("open %s: %w", tunModuleCharPath, err)
	}

	defer func() {
		if err != nil {
			unix.Close(linkFd)
		}
	}()

	const modName = "ip"
	err = unix.IoctlSetString(linkFd, unix.I_PUSH, modName)
	if err != nil {
		return tun, fmt.Errorf("push tunnel to ip: %w", err)
	}

	err = unix.IoctlSetPointerInt(linkFd, unix.IF_UNITSEL, skppa)
	if err != nil {
		return tun, fmt.Errorf("set tunnel ppa: %w", err)
	}

	var tunLinkReq = unix.I_LINK
	if config.Persist {
		tunLinkReq = unix.I_PLINK
	}

	muxid, err := unix.IoctlSetIntRetInt(ipFd, tunLinkReq, linkFd)
	if err != nil {
		return tun, fmt.Errorf("link tunnel: %w", err)
	}

	var lifreq unix.Lifreq
	lifreq.SetName(tunName)
	*(*int32)(unsafe.Pointer(&lifreq.Lifru[0])) = int32(muxid)

	err = unix.IoctlLifreq(ipFd, unix.SIOCSLIFMUXID, &lifreq)
	if err != nil {
		return tun, fmt.Errorf("set link muxid: %w", err)
	}

	if tunLinkReq == unix.I_PLINK {
		defer func() {
			if err != nil {
				Destroy(tunName)
			}
		}()
	}

	if err = unix.SetNonblock(dataFd, true); err != nil {
		return tun, fmt.Errorf("set nonblock: %w", err)
	}

	tun.name = tunName
	tun.dataFile = os.NewFile(uintptr(dataFd), tun.name)
	tun.linkFile = os.NewFile(uintptr(linkFd), tunModuleCharPath)
	tun.buff = make([]byte, 0, tunReadBufferLen)
	return
}

func tunNewPPA(dataFd int, ppa int) (int, error) {

	const (
		TUNNEWPPA = 0x540001
		TUNSETPPA = 0x540002
		TUNGETPPA = 0x540003
	)

	cache := ppa
	ioc := unix.Strioctl{
		Len: int32(unsafe.Sizeof(cache)),
		Dp:  (*int8)(unsafe.Pointer(&cache)),
		Cmd: TUNNEWPPA,
	}

	skppa, err := unix.IoctlSetStrioctlRetInt(dataFd, unix.I_STR, &ioc)
	if err != nil {
		return skppa, err
	}

	if ppa > -1 && ppa != skppa {
		return -1, errors.New(
			"kernel allocated a different ppa than requested",
		)
	}

	return skppa, err
}

func (tun *tunDevice) Close() error {

	if tun.closed.Swap(true) {
		return fmt.Errorf("close: %w", os.ErrClosed)
	}

	var err1, err2 error
	if tun.dataFile != nil {
		err1 = tun.dataFile.Close()
	}

	if tun.linkFile != nil {
		err2 = tun.linkFile.Close()
	}

	if err1 != nil {
		return fmt.Errorf("close: close data file: %w", err1)
	}

	if err2 != nil {
		return fmt.Errorf("close: close link file: %w", err2)
	}

	return nil
}

func (tun *tunDevice) Read(b []byte) (int, error) {

	if tun.closed.Load() {
		return 0, fmt.Errorf("read: %w", os.ErrClosed)
	}

	tun.readMutex.Lock()
	defer tun.readMutex.Unlock()

	n, err := tun.readPacket(b)
	if err != nil {
		return 0, fmt.Errorf("read: %w", err)
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

	n, err := tun.dataFile.Write(b[:plen])
	if err != nil {
		return 0, fmt.Errorf("write: %w", err)
	}

	return n, err
}

func (tun *tunDevice) readPacket(b []byte) (int, error) {

	totalLen, err := tcpip.TotalLen(tun.unread)
	if err != nil {
		if err == tcpip.ErrShortBuffer {
			cn := copy(tun.buff[:len(tun.unread)], tun.unread)
			n, err := tun.dataFile.Read(tun.buff[cn:cap(tun.buff)])
			if err != nil {
				return 0, err
			}
			tun.unread = tun.buff[:cn+n]
		} else {
			return 0, err
		}

	} else {

		if len(b) < totalLen {
			return 0, ErrShortBuffer
		}

		n := copy(b, tun.unread[:totalLen])
		tun.unread = tun.unread[totalLen:]
		return n, err
	}

	totalLen, err = tcpip.TotalLen(tun.unread)
	if err != nil {
		if err == tcpip.ErrShortBuffer {
			return 0, errors.New("short ip packet")
		}
		return 0, err
	}

	if len(b) < totalLen {
		return 0, ErrShortBuffer
	}

	n := copy(b, tun.unread[:totalLen])
	tun.unread = tun.unread[totalLen:]
	return n, err

}

func Destroy(name string) error {

	ipFile, err := os.OpenFile(ipModulePath, tunOpenMode, 0)
	if err != nil {
		return err
	}

	defer ipFile.Close()

	var lifreq unix.Lifreq
	lifreq.SetName(name)

	ipFileFd := int(ipFile.Fd())

	err = unix.IoctlLifreq(ipFileFd, unix.SIOCGLIFMUXID, &lifreq)
	if err != nil {
		return fmt.Errorf("get link muxid: %w", err)
	}

	ipMuxid := *(*int32)(unsafe.Pointer(&lifreq.Lifru[0]))

	err = unix.IoctlSetInt(ipFileFd, unix.I_PUNLINK, int(ipMuxid))
	if err != nil {
		return fmt.Errorf("unlink tunnel: %w", err)
	}

	return nil
}

func (tun *tunDevice) Name() (name string) {
	return tun.name
}

func (tun *tunDevice) Destroy() error {
	if err := Destroy(tun.name); err != nil {
		return fmt.Errorf("destroy: %w", err)
	}
	return nil
}

func getTunIndex(name string) (int, error) {

	if len(name) == 0 {
		return -1, nil
	}

	const tunPrefix = "tun"
	var errInvalid = errors.New("interface name must be tun[0-9]+")

	if len(name) >= unix.IFNAMSIZ {
		return -1, errors.New("interface name too long")
	}

	if !strings.HasPrefix(name, tunPrefix) {
		return -1, errInvalid
	}

	firstDigit := strings.IndexAny(name, "0123456789")
	if firstDigit == -1 {
		return -1, errInvalid
	}

	if firstDigit == 0 {
		return -1, errInvalid
	}

	lastNonDigit := -1
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] < '0' || name[i] > '9' {
			lastNonDigit = i
			break
		}
	}

	ppa, err := strconv.Atoi(name[lastNonDigit+1:])
	if err != nil {
		return -1, err
	}

	return ppa, nil
}
