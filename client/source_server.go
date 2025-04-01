package client

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/netc"
)

type SourceServer struct {
	src    *Source
	addr   string
	logger *slog.Logger
}

func NewSourceServer(src *Source, fwd model.Forward, addr string, logger *slog.Logger) *SourceServer {
	return &SourceServer{
		src:    src,
		addr:   addr,
		logger: logger.With("source", fwd, "addr", addr),
	}
}

func (s *SourceServer) Run(ctx context.Context) error {
	s.logger.Debug("starting source server")
	l, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("source server listen: %w", err)
	}
	defer l.Close()

	go func() {
		<-ctx.Done()
		l.Close()
	}()

	s.logger.Info("listening for conns")
	for {
		conn, err := l.Accept()
		if err != nil {
			return fmt.Errorf("server accept: %w", err)
		}

		go s.runConn(ctx, conn)
	}
}

func (s *SourceServer) runConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	s.logger.Debug("received conn", "remote", conn.RemoteAddr())

	if err := s.runConnErr(ctx, conn); err != nil {
		s.logger.Warn("source conn error", "err", err)
	}
}

func (s *SourceServer) runConnErr(ctx context.Context, conn net.Conn) error {
	dstConn, err := s.src.DialContext(ctx, "", "")
	if err != nil {
		return fmt.Errorf("dial destination: %w", err)
	}
	defer dstConn.Close()

	if proxyConn, ok := dstConn.(model.ProxyProtoConn); ok {
		if err := proxyConn.WriteProxyHeader(conn.RemoteAddr(), conn.LocalAddr()); err != nil {
			return fmt.Errorf("write proxy header: %w", err)
		}
	}

	err = netc.Join(ctx, conn, dstConn)
	s.logger.Debug("disconnected conns", "err", err)

	return nil
}
