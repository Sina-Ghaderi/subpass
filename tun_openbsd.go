//go:build openbsd

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

	"golang.org/x/sys/unix"
)

type tunDevice struct {
	file       *os.File
	readMutex  sync.Mutex
	writeMutex sync.Mutex
	closed     atomic.Bool
	name       string
}

type Tun interface {
	Name() string
	io.ReadWriteCloser
}

type Config struct{ Name string }

func defaltOSparms() Config { return Config{} }

func (tun *tunDevice) Name() string { return tun.name }

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
