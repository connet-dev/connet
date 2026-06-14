package pbconnect

import (
	"fmt"
	"io"

	"github.com/connet-dev/connet/pkg/proto"
	"github.com/connet-dev/connet/pkg/proto/pberror"
)

func ReadRequest(r io.Reader, v proto.WireVersion) (*Request, error) {
	req := &Request{}
	if err := proto.Read(r, req, v); err != nil {
		return nil, err
	}
	return req, nil
}

func ReadResponse(r io.Reader, v proto.WireVersion) (*Response, error) {
	resp := &Response{}
	if err := proto.Read(r, resp, v); err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, resp.Error
	}
	return resp, nil
}

func WriteError(w io.Writer, v proto.WireVersion, code pberror.Code, msg string, args ...any) error {
	pbErr := pberror.NewError(code, msg, args...)
	if err := proto.Write(w, &Response{Error: pbErr}, v); err != nil {
		return fmt.Errorf("write err response '%w': %w", pbErr, err)
	}
	return pbErr
}
