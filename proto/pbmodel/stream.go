package pbmodel

import (
	"encoding/binary"
	"io"

	"google.golang.org/protobuf/proto"
)

func Write(w io.Writer, msg proto.Message) error {
	msgBytes, err := proto.Marshal(msg)
	if err != nil {
		return err
	}
	szBytes := make([]byte, 0, 8)
	szBytes = binary.BigEndian.AppendUint64(szBytes, uint64(len(msgBytes)))
	if _, err := w.Write(szBytes); err != nil {
		if aperr := GetAppError(err); aperr != nil {
			return &Error{
				Code:    Error_Code(aperr.ErrorCode),
				Message: aperr.ErrorMessage,
			}
		}
		return err
	}
	_, err = w.Write(msgBytes)
	if err != nil {
		if aperr := GetAppError(err); aperr != nil {
			return &Error{
				Code:    Error_Code(aperr.ErrorCode),
				Message: aperr.ErrorMessage,
			}
		}
	}
	return err
}

func Read(r io.Reader, msg proto.Message) error {
	szBytes := make([]byte, 8)

	_, err := io.ReadFull(r, szBytes)
	if err != nil {
		if aperr := GetAppError(err); aperr != nil {
			return &Error{
				Code:    Error_Code(aperr.ErrorCode),
				Message: aperr.ErrorMessage,
			}
		}
		return err
	}
	sz := binary.BigEndian.Uint64(szBytes)

	msgBytes := make([]byte, sz)
	_, err = io.ReadFull(r, msgBytes)
	if err != nil {
		if aperr := GetAppError(err); aperr != nil {
			return &Error{
				Code:    Error_Code(aperr.ErrorCode),
				Message: aperr.ErrorMessage,
			}
		}
		return err
	}

	return proto.Unmarshal(msgBytes, msg)
}
