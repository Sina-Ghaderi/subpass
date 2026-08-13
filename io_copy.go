package subpass

import (
	"errors"
	"io"
)

func Copy(dst io.Writer, src io.Reader) (written int64, err error) {

	buff := make([]byte, 64*1024)
	offset := 0

	for {
		nr, er := src.Read(buff[offset:])
		if nr > 0 {
			if offset != 0 {
				nr += offset
				offset = 0
			}

		retry:
			nw, ew := dst.Write(buff[:nr])
			if nw < 0 || nr < nw {
				nw = 0
				if ew == nil {
					ew = errors.New("invalid write result")
				}
			}

			written += int64(nw)

			if ew != nil {
				if errors.Is(ew, ErrShortBuffer) {
					offset = copy(buff, buff[:nr])
					continue
				}
				err = ew
				break
			}

			if nr > nw {
				copy(buff, buff[nw:nr])
				nr = nr - nw
				goto retry
			}
		}

		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}

	return written, err
}
