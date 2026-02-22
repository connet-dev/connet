package pbconnect

import (
	"fmt"
	"io"

	"github.com/connet-dev/connet/proto"
	"github.com/connet-dev/connet/proto/pberror"
)

func ReadRequest(r io.Reader) (*Request, error) {
	req := &Request{}
	if err := proto.Read(r, req); err != nil {
		return nil, err
	}
	return req, nil
}

func ReadResponse(r io.Reader) (*Response, error) {
	resp := &Response{}
	if err := proto.Read(r, resp); err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, resp.Error
	}
	return resp, nil
}

func WriteError(w io.Writer, code pberror.Code, msg string, args ...any) error {
	pbErr := pberror.NewError(code, msg, args...)
	if err := proto.Write(w, &Response{Error: pbErr}); err != nil {
		return fmt.Errorf("write err response '%w': %w", pbErr, err)
	}
	return pbErr
}
