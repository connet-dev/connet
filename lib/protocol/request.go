package protocol

import "io"

type RequestType uint32

const (
	RequestListen  RequestType = 1
	RequestConnect RequestType = 2
)

func (t RequestType) Write(w io.Writer, s string) error {
	return writeRequest(w, t, s)
}

func ReadRequest(r io.Reader) (RequestType, string, error) {
	t, err := readUint32(r)
	if err != nil {
		return 0, "", err
	}
	s, err := readString(r)
	if err != nil {
		return 0, "", err
	}
	return RequestType(t), s, nil
}

func writeRequest(w io.Writer, t RequestType, s string) error {
	if err := writeUint32(w, uint32(t)); err != nil {
		return err
	}
	return writeString(w, s)
}
