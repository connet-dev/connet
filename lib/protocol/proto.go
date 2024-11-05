package protocol

import (
	"encoding/binary"
	"io"

	"github.com/klev-dev/kleverr"
)

func readUint32(r io.Reader) (uint32, error) {
	buff := make([]byte, 4)
	if _, err := io.ReadFull(r, buff); err != nil {
		return 0, kleverr.Newf("could not read: %w", err)
	}
	return binary.BigEndian.Uint32(buff), nil
}

func readString(r io.Reader) (string, error) {
	ln, err := readUint32(r)
	if err != nil {
		return "", err
	}
	buff := make([]byte, ln)
	if _, err := io.ReadFull(r, buff); err != nil {
		return "", kleverr.Newf("could not read: %w", err)
	}
	return string(buff), nil // TODO utf decode?
}

func writeUint32(w io.Writer, n uint32) error {
	data := binary.BigEndian.AppendUint32(nil, n)
	_, err := w.Write(data)
	return err
}

func writeString(w io.Writer, s string) error {
	if err := writeUint32(w, uint32(len(s))); err != nil {
		return err
	}
	_, err := w.Write([]byte(s))
	return err
}
