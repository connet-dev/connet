package pb

import (
	"encoding/binary"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"
)

func NewError(code Error_Code, msg string, args ...any) *Error {
	return &Error{
		Code:    code,
		Message: fmt.Sprintf(msg, args...),
	}
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s (%d)", e.Message, e.Code)
}

func Write(w io.Writer, msg proto.Message) error {
	msgBytes, err := proto.Marshal(msg)
	if err != nil {
		return err
	}
	szBytes := make([]byte, 0, 8)
	szBytes = binary.BigEndian.AppendUint64(szBytes, uint64(len(msgBytes)))
	if _, err := w.Write(szBytes); err != nil {
		return err
	}
	_, err = w.Write(msgBytes)
	return err
}

func Read(r io.Reader, msg proto.Message) error {
	szBytes := make([]byte, 8)

	_, err := io.ReadFull(r, szBytes)
	if err != nil {
		return err
	}
	sz := binary.BigEndian.Uint64(szBytes)

	msgBytes := make([]byte, sz)
	_, err = io.ReadFull(r, msgBytes)
	if err != nil {
		return err
	}

	return proto.Unmarshal(msgBytes, msg)
}
