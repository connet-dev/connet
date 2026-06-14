package proto

import (
	"encoding/binary"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"

	"github.com/connet-dev/connet/pkg/proto/pberror"
)

// maxMessageSize is the maximum allowed protobuf message size (16 MB).
const maxMessageSize = 16 * 1024 * 1024

type WireVersion struct{ int } // TODO remove in 0.18

var (
	WireVersion1 = WireVersion{8} // TODO remove in 0.18
	WireVersion2 = WireVersion{4}
)

func Write(w io.Writer, msg proto.Message, v WireVersion) error {
	msgBytes, err := proto.Marshal(msg)
	if err != nil {
		return err
	}
	szBytes := make([]byte, 0, v.int)
	if v == WireVersion1 {
		szBytes = binary.BigEndian.AppendUint64(szBytes, uint64(len(msgBytes)))
	} else {
		szBytes = binary.BigEndian.AppendUint32(szBytes, uint32(len(msgBytes)))
	}
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

func Read(r io.Reader, msg proto.Message, v WireVersion) error {
	szBytes := make([]byte, v.int)

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

	var sz int
	if v == WireVersion1 {
		sz = int(binary.BigEndian.Uint64(szBytes))
	} else {
		sz = int(binary.BigEndian.Uint32(szBytes))
	}
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
