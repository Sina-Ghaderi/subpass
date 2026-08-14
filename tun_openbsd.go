//go:build openbsd

package subpass

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
)

const tunCharPathFormat = "/dev/tun%d"
const tunOpenMode = unix.O_CLOEXEC | unix.O_RDWR

type tunDevice struct {
	file       *os.File
	readMutex  sync.Mutex
	writeMutex sync.Mutex
	closed     atomic.Bool
	name       string
}

type Tun interface {
	Name() string
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
}

type Config struct{ Name string }

func defaltOSparms() Config { return Config{} }

func (tun *tunDevice) Name() string { return tun.name }

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
	return
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
