package connet

import (
	"context"
	"log/slog"
	"net"

	"github.com/keihaya-com/connet/netc"
	"github.com/keihaya-com/connet/pb"
	"github.com/keihaya-com/connet/pbc"
	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
)

type destinationsDialer struct {
	destinations map[Forward]string
	logger       *slog.Logger
}

func (s *destinationsDialer) runRequest(ctx context.Context, stream quic.Stream) {
	defer stream.Close()

	if err := s.runRequestErr(ctx, stream); err != nil {
		s.logger.Warn("error handling conn", "err", err)
	}
}

func (s *destinationsDialer) runRequestErr(ctx context.Context, stream quic.Stream) error {
	req, err := pbc.ReadRequest(stream)
	if err != nil {
		return err
	}

	switch {
	case req.Connect != nil:
		return s.connect(ctx, stream, NewForwardFromPB(req.Connect.To))
	default:
		return s.unknown(ctx, stream, req)
	}
}

func (s *destinationsDialer) connect(ctx context.Context, stream quic.Stream, target Forward) error {
	logger := s.logger.With("target", target)
	addr, ok := s.destinations[target]
	if !ok {
		err := pb.NewError(pb.Error_DestinationNotFound, "%s not found on this client", target)
		if err := pb.Write(stream, &pbc.Response{Error: err}); err != nil {
			return kleverr.Newf("could not write error response: %w", err)
		}
		return err
	}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		err := pb.NewError(pb.Error_DestinationDialFailed, "%s could not be dialed: %v", target, err)
		if err := pb.Write(stream, &pbc.Response{Error: err}); err != nil {
			return kleverr.Newf("could not write error response: %w", err)
		}
		return err
	}
	defer conn.Close()

	if err := pb.Write(stream, &pbc.Response{}); err != nil {
		return kleverr.Newf("could not write response: %w", err)
	}

	logger.Debug("joining from server")
	err = netc.Join(ctx, stream, conn)
	logger.Debug("disconnected from server", "err", err)

	return nil
}

func (s *destinationsDialer) unknown(ctx context.Context, stream quic.Stream, req *pbc.Request) error {
	err := pb.NewError(pb.Error_RequestUnknown, "unknown request: %v", req)
	if err := pb.Write(stream, &pbc.Response{Error: err}); err != nil {
		return kleverr.Newf("cannot write error response: %w", err)
	}
	return err
}
