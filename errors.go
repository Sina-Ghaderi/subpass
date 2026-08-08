package subpass

import (
	"errors"

	"github.com/sina-ghaderi/subpass/tcpip"
)

var ErrShortBuffer = errors.New("packet length exceeds user buffer")

func checkPacketLen(b []byte) (uint8, int, error) {
	var totalLen int
	totalLen, err := tcpip.TotalLen(b)
	switch err {
	case nil:
		return b[0] >> 4, totalLen, err
	case tcpip.ErrShortBuffer:
		return 0, totalLen, ErrShortBuffer
	default:
		return 0, totalLen, err
	}
}
