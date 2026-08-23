package subpass

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"github.com/sina-ghaderi/tcpip"
	"github.com/sina-ghaderi/virtio/net"
	"github.com/sina-ghaderi/virtio/vhostnet"
	"golang.org/x/sys/unix"
)

type tunDeviceVHost struct {
	readMutex   sync.Mutex
	writeMutex  sync.Mutex
	file        *os.File
	vhostDevice *vhostnet.Device
	closed      atomic.Bool
	name        string
}

func openVHostNetTun(config *Config) (*tunDeviceVHost, error) {

	dev, err := createTunVHostNet(config)
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

func createTunVHostNet(config *Config) (tun *tunDeviceVHost, err error) {
	tun = &tunDeviceVHost{}
	tun.file, err = createGenericTun(config, unix.IFF_VNET_HDR)
	if err != nil {
		return
	}

	tun.name = tun.file.Name()
	if err = setTunNetHdrSize(tun.file); err != nil {
		return tun, fmt.Errorf("set virtio nethdr size: %w", err)
	}

	device, err := vhostnet.NewDevice(tun.file, config.VRingSize)
	if err != nil {
		return
	}

	tun.vhostDevice = device
	return
}

func (tun *tunDeviceVHost) Name() (name string) { return tun.name }

func (tun *tunDeviceVHost) Destroy() error {
	if err := Destroy(tun.name); err != nil {
		return fmt.Errorf("destroy: %w", err)
	}
	return nil
}

func (tun *tunDeviceVHost) Read(b []byte) (int, error) {

	if tun.closed.Load() {
		return 0, fmt.Errorf("read: %w", os.ErrClosed)
	}

	tun.readMutex.Lock()
	defer tun.readMutex.Unlock()

	vhost, packet, err := tun.vhostDevice.ReceivePacket()
	if err != nil {
		return 0, fmt.Errorf("read: %w", err)
	}

	fmt.Printf("%#v\n", vhost)

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

	if len(b) < len(packet) {
		return 0, fmt.Errorf("read: %w", ErrShortBuffer)
	}

	cp := copy(b, packet)
	return cp, nil
}

func (tun *tunDeviceVHost) Write(b []byte) (int, error) {

	if tun.closed.Load() {
		return 0, fmt.Errorf("write: %w", os.ErrClosed)
	}

	tun.writeMutex.Lock()
	defer tun.writeMutex.Unlock()

	_, plen, err := checkPacketLen(b)
	if err != nil {
		return 0, fmt.Errorf("write: %w", err)
	}

	vhdr := net.VirtioNetHdr{}
	fmt.Println("brefore TransmitPacket")
	err = tun.vhostDevice.TransmitPacket(vhdr, b[:plen])
	if err != nil {
		return 0, fmt.Errorf("write: %w", err)
	}

	return plen, nil
}

func (tun *tunDeviceVHost) Close() error {

	if tun.closed.Swap(true) {
		return fmt.Errorf("close: %w", os.ErrClosed)
	}

	var err error
	if tun.file != nil {
		err = tun.file.Close()
	}

	var err2 error
	if tun.vhostDevice != nil {
		err2 = tun.vhostDevice.Close()
	}

	if err != nil {
		return fmt.Errorf("close: %w", err)
	}

	if err2 != nil {
		return fmt.Errorf("close: %w", err2)
	}

	return err
}
