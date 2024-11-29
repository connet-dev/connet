package connet

import (
	"context"
	"log/slog"
	"net"

	"github.com/keihaya-com/connet/model"
	"github.com/keihaya-com/connet/netc"
	"github.com/keihaya-com/connet/pb"
	"github.com/keihaya-com/connet/pbc"
	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
)

type destinationsDialer struct {
	destinations map[model.Forward]clientForwardConfig
	logger       *slog.Logger
}

func (s *destinationsDialer) runRequest(ctx context.Context, stream quic.Stream, from model.RouteOption) {
	defer stream.Close()

	if err := s.runRequestErr(ctx, stream, from); err != nil {
		s.logger.Warn("error handling conn", "err", err)
	}
}

func (s *destinationsDialer) runRequestErr(ctx context.Context, stream quic.Stream, from model.RouteOption) error {
	req, err := pbc.ReadRequest(stream)
	if err != nil {
		return err
	}

	switch {
	case req.Connect != nil:
		return s.connect(ctx, stream, model.NewForwardFromPB(req.Connect.To), from)
	default:
		return s.unknown(ctx, stream, req)
	}
}

func (s *destinationsDialer) connect(ctx context.Context, stream quic.Stream, target model.Forward, from model.RouteOption) error {
	logger := s.logger.With("target", target)
	fc, ok := s.destinations[target]
	if !ok {
		err := pb.NewError(pb.Error_DestinationNotFound, "%s not found on this client", target)
		if err := pb.Write(stream, &pbc.Response{Error: err}); err != nil {
			return kleverr.Newf("could not write error response: %w", err)
		}
		return err
	}
	if !fc.route.AllowFrom(from) {
		err := pb.NewError(pb.Error_DestinationNotFound, "%s not found on this client", target)
		if err := pb.Write(stream, &pbc.Response{Error: err}); err != nil {
			return kleverr.Newf("could not write error response: %w", err)
		}
		return err
	}

	conn, err := net.Dial("tcp", fc.addr)
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
