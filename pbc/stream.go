package pbc

import (
	"fmt"
	"io"

	"github.com/connet-dev/connet/pb"
)

func ReadRequest(r io.Reader) (*Request, error) {
	req := &Request{}
	if err := pb.Read(r, req); err != nil {
		return nil, err
	}
	return req, nil
}

func ReadResponse(r io.Reader) (*Response, error) {
	resp := &Response{}
	if err := pb.Read(r, resp); err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, resp.Error
	}
	return resp, nil
}

func WriteError(w io.Writer, code pb.Error_Code, msg string, args ...any) error {
	err := pb.NewError(code, msg, args...)
	if err := pb.Write(w, &Response{Error: err}); err != nil {
		return fmt.Errorf("write err response: %w", err)
	}
	return err
}
