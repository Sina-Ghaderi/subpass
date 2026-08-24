//go:build linux

package subpass

import (
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"

	"github.com/sina-ghaderi/tcpip"
	"github.com/sina-ghaderi/virtio/offloads"
	"golang.org/x/sys/unix"
)

type tunDeviceOffload struct {
	offloads   io.ReadWriteCloser
	closed     atomic.Bool
	name       string
	readMutex  sync.Mutex
	writeMutex sync.Mutex
}

func openOffloadedTun(config *Config) (tun *tunDeviceOffload, err error) {

	file, err := createTunWithFlags(config, unix.IFF_VNET_HDR)
	if err != nil {
		err = fmt.Errorf("open device: %w", err)
		return
	}

	defer func() {
		if err != nil {
			file.Close()
		}
	}()

	tun = &tunDeviceOffload{name: file.Name()}
	if tun.offloads, err = offloads.NewOffloads(file); err != nil {
		err = fmt.Errorf("open device: %w", err)
		return
	}

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

	n, err := tun.offloads.Read(b)
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

	n, err := tun.offloads.Write(b)
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
	if tun.offloads != nil {
		err = tun.offloads.Close()
	}

	if err != nil {
		return fmt.Errorf("close: %w", err)
	}

	return err
}
