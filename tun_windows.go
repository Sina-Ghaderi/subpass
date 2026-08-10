//go:build windows

package subpass

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"github.com/sina-ghaderi/subpass/internal/wintun"
	"github.com/sina-ghaderi/subpass/tcpip"
	"golang.org/x/sys/windows"
)

const (
	defualtName = "Client"
	defaultType = "Wintun"
)

type Config struct {
	Name         string
	Type         string
	RingCapacity uint32
	GUID         *windows.GUID
}

func defaltOSparms() Config {
	return Config{
		Name:         defualtName,
		Type:         defaultType,
		RingCapacity: 1 << 22,
	}
}

type tunDevice struct {
	session   wintun.Session
	adaptor   *wintun.Adapter
	onceClose sync.Once
	readWait  windows.Handle
	closed    atomic.Bool
	running   sync.WaitGroup
	name      string
}

func (tun *tunDevice) ID() uint64 { return tun.adaptor.LUID() }
func WintunDriverVersion() string { return wintun.Version() }

func openTunDevice(config *Config) (*tunDevice, error) {
	dev, err := createTunDevice(config)
	if err != nil {
		err = fmt.Errorf("create device: %w", err)
		dev = nil
	}
	return dev, err
}

func createTunDevice(config *Config) (tun *tunDevice, err error) {

	err = checkWintunConfig(config)
	if err != nil {
		return
	}

	adapter, err := wintun.OpenAdapter(config.Name)
	if err != nil {
		adapter, err = wintun.CreateAdapter(config.Name, config.Type, config.GUID)
		if err != nil {
			return tun, fmt.Errorf("create tunnel: %w", err)
		}
	}

	ssn, err := adapter.StartSession(config.RingCapacity)
	if err != nil {
		adapter.Close()
		return tun, fmt.Errorf("start tunnel session: %w", err)
	}

	tun = &tunDevice{readWait: ssn.ReadWaitEvent()}
	tun.name = config.Name
	tun.adaptor = adapter
	tun.session = ssn
	return
}

func (tun *tunDevice) Read(b []byte) (int, error) {

	tun.running.Add(1)
	defer tun.running.Done()

retry:
	if tun.closed.Load() {
		return 0, fmt.Errorf("read: %w", os.ErrClosed)
	}

	packet, err := tun.session.ReceivePacket()
	switch err {
	case nil:
		cp := copy(b, packet)
		tun.session.ReleaseReceivePacket(packet)

		totalLen, err := tcpip.TotalLen(packet)
		if err != nil {
			if err == tcpip.ErrShortBuffer {
				return 0, fmt.Errorf("read: short ip packet")
			}
			return 0, fmt.Errorf("read: %w", err)
		}

		if totalLen != len(packet) {
			return 0, fmt.Errorf("read: invalid ip packet length")
		}

		if cp < len(packet) {
			return 0, fmt.Errorf("read: %w", ErrShortBuffer)
		}

		return cp, err
	case windows.ERROR_NO_MORE_ITEMS:
		windows.WaitForSingleObject(tun.readWait, windows.INFINITE)
		goto retry
	case windows.ERROR_HANDLE_EOF:
		return 0, fmt.Errorf("read: %w", os.ErrClosed)
	case windows.ERROR_INVALID_DATA:
		return 0, errors.New("read: send ring corrupt")
	}

	return 0, fmt.Errorf("read: %w", err)
}

func (tun *tunDevice) Write(b []byte) (int, error) {
	tun.running.Add(1)
	defer tun.running.Done()

	if tun.closed.Load() {
		return 0, fmt.Errorf("write: %w", os.ErrClosed)
	}

	_, lb, err := checkPacketLen(b)
	if err != nil {
		return 0, fmt.Errorf("write: %w", err)
	}

	if lb > wintun.PacketSizeMax {
		return 0, errors.New("write: buffer size too large")
	}

	packet, err := tun.session.AllocateSendPacket(lb)
	switch err {
	case nil:
		cp := copy(packet, b[:lb])
		tun.session.SendPacket(packet)
		return cp, nil
	case windows.ERROR_HANDLE_EOF:
		return 0, fmt.Errorf("write: %w", os.ErrClosed)
	case windows.ERROR_BUFFER_OVERFLOW:
		return 0, nil
	}

	return 0, fmt.Errorf("write: %w", err)
}

func (tun *tunDevice) Close() error {

	if tun.closed.Swap(true) {
		return fmt.Errorf("close: %w", os.ErrClosed)
	}

	var err error
	tun.onceClose.Do(func() {
		tun.closed.Store(true)
		windows.SetEvent(tun.readWait)
		tun.running.Wait()
		tun.session.End()
		if tun.adaptor != nil {
			err = tun.adaptor.Close()
		}
	})

	if err != nil {
		err = fmt.Errorf("close: %w", err)
	}
	return err
}

func checkWintunConfig(config *Config) (err error) {

	switch {
	case config.RingCapacity > wintun.RingCapacityMax:
		err = errors.New("ring capacity is too high")
	case config.RingCapacity < wintun.RingCapacityMin:
		err = errors.New("ring capacity is too low")
	case (config.RingCapacity & (config.RingCapacity - 1)) != 0:
		err = errors.New("ring capacity must be a power of two")
	case len(config.Name) == 0:
		err = errors.New("tunnel name cannot be empty")
	case len(config.Type) == 0:
		err = errors.New("tunnel type cannot be empty")
	}

	return
}

func (tun *tunDevice) Name() (name string, err error) {
	return tun.name, err
}

func (tun *tunDevice) Destroy() error {
	return errors.New("operation not supported on this platform")
}

func Destroy(uint64) error {
	return errors.New("operation not supported on this platform")
}
