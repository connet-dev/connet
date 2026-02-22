package proto

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/connet-dev/connet/proto/pberror"
	"google.golang.org/protobuf/proto"
)

// maxMessageSize is the maximum allowed protobuf message size (16 MB).
const maxMessageSize = 16 * 1024 * 1024

func Write(w io.Writer, msg proto.Message) error {
	msgBytes, err := proto.Marshal(msg)
	if err != nil {
		return err
	}
	szBytes := make([]byte, 0, 8) // TODO use int32 instead
	szBytes = binary.BigEndian.AppendUint64(szBytes, uint64(len(msgBytes)))
	if _, err := w.Write(szBytes); err != nil {
		if aperr := pberror.GetAppError(err); aperr != nil {
			return &pberror.Error{
				Code:    pberror.Code(aperr.ErrorCode),
				Message: aperr.ErrorMessage,
			}
		}
		return err
	}
	_, err = w.Write(msgBytes)
	if err != nil {
		if aperr := pberror.GetAppError(err); aperr != nil {
			return &pberror.Error{
				Code:    pberror.Code(aperr.ErrorCode),
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
		if aperr := pberror.GetAppError(err); aperr != nil {
			return &pberror.Error{
				Code:    pberror.Code(aperr.ErrorCode),
				Message: aperr.ErrorMessage,
			}
		}
		return err
	}
	sz := binary.BigEndian.Uint64(szBytes)
	if sz > maxMessageSize {
		return fmt.Errorf("message size %d exceeds maximum %d", sz, maxMessageSize)
	}

	msgBytes := make([]byte, sz)
	_, err = io.ReadFull(r, msgBytes)
	if err != nil {
		if aperr := pberror.GetAppError(err); aperr != nil {
			return &pberror.Error{
				Code:    pberror.Code(aperr.ErrorCode),
				Message: aperr.ErrorMessage,
			}
		}
		return err
	}

	return proto.Unmarshal(msgBytes, msg)
}
