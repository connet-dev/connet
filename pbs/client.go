package pbs

import (
	"context"
	"crypto/x509"

	"github.com/keihaya-com/connet/pb"
	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
)

type Client interface {
	Authenticate(ctx context.Context, token string) (*pb.AddrPort, error)
	Relay(ctx context.Context, cert *x509.Certificate, destinations []*pb.Binding, sources []*pb.Binding) error
}

func NewClient(conn quic.Connection) (Client, error) {
	return &client{conn}, nil
}

type client struct {
	conn quic.Connection
}

func (p *client) Authenticate(ctx context.Context, token string) (*pb.AddrPort, error) {
	stream, err := p.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, kleverr.Newf("cannot open auth stream: %w", err)
	}
	defer stream.Close()

	if err := pb.Write(stream, &Authenticate{
		Token: token,
	}); err != nil {
		return nil, kleverr.Newf("cannot write auth request: %w", err)
	}

	resp := &AuthenticateResp{}
	if err := pb.Read(stream, resp); err != nil {
		return nil, kleverr.Newf("cannot read auth response: %w", err)
	}
	if resp.Error != nil {
		return nil, kleverr.Ret(resp.Error)
	}
	return resp.Public, nil
}

func (p *client) Relay(ctx context.Context, cert *x509.Certificate, destinations []*pb.Binding, sources []*pb.Binding) error {
	_, err := p.request(ctx, &Request{
		Relay: &Request_Relay{
			Certificate:  cert.Raw,
			Destinations: destinations,
			Sources:      sources,
		},
	})
	return err
}

func (p *client) request(ctx context.Context, req *Request) (*Response, error) {
	stream, err := p.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, kleverr.Newf("cannot open request stream: %w", err)
	}
	defer stream.Close()

	if err := pb.Write(stream, req); err != nil {
		return nil, kleverr.Newf("cannot write request: %w", err)
	}

	return ReadResponse(stream)
}
