package pbclient

import (
	"fmt"
	"io"

	"github.com/connet-dev/connet/proto"
)

func ReadRequest(r io.Reader) (*Request, error) {
	req := &Request{}
	if err := proto.Read(r, req); err != nil {
		return nil, fmt.Errorf("server request read: %w", err)
	}
	return req, nil
}

func ReadResponse(r io.Reader) (*Response, error) {
	resp := &Response{}
	if err := proto.Read(r, resp); err != nil {
		return nil, fmt.Errorf("server response read: %w", err)
	}
	if resp.Error != nil {
		return nil, resp.Error
	}
	return resp, nil
}
