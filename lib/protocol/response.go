package protocol

import (
	"fmt"
	"io"
)

type ResponseType int32

const (
	ResponseOk              ResponseType = 0
	ResponseInvalidRequest  ResponseType = 1
	ResponseListenNotFound  ResponseType = 2
	ResponseListenNotDialed ResponseType = 3
)

func (t ResponseType) Write(w io.Writer, s string) error {
	return writeResponse(w, t, s)
}

func ReadResponse(r io.Reader) (string, error) {
	switch t, s, err := readResponse(r); {
	case err != nil:
		return "", err
	case t == ResponseOk:
		return s, nil
	default:
		return "", fmt.Errorf("error %d: %s", t, s)
	}
}

func readResponse(r io.Reader) (ResponseType, string, error) {
	t, err := readUint32(r)
	if err != nil {
		return 0, "", err
	}
	s, err := readString(r)
	if err != nil {
		return 0, "", err
	}
	return ResponseType(t), s, nil
}

func writeResponse(w io.Writer, t ResponseType, s string) error {
	if err := writeUint32(w, uint32(t)); err != nil {
		return err
	}
	return writeString(w, s)
}
