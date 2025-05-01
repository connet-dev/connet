package pbconnect

import (
	"fmt"
	"io"

	"github.com/connet-dev/connet/proto"
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

func WriteError(w io.Writer, code proto.Error_Code, msg string, args ...any) error {
	err := proto.NewError(code, msg, args...)
	if err := proto.Write(w, &Response{Error: err}); err != nil {
		return fmt.Errorf("write err response: %w", err)
	}
	return err
}
