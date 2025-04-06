package connet

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/netc"
)

func (c *Client) SourceTCP(ctx context.Context, cfg SourceConfig, addr string) error {
	src, err := c.Source(ctx, cfg)
	if err != nil {
		return err
	}
	tcp, err := NewTCPSource(src, cfg.Forward, addr, c.logger)
	if err != nil {
		return err
	}
	go tcp.Run(ctx)
	return nil
}

type TCPSource struct {
	src    Source
	addr   string
	logger *slog.Logger
}

func NewTCPSource(src Source, fwd model.Forward, addr string, logger *slog.Logger) (*TCPSource, error) {
	return &TCPSource{
		src:    src,
		addr:   addr,
		logger: logger.With("source", fwd, "addr", addr),
	}, nil
}

func (s *TCPSource) Run(ctx context.Context) error {
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

func (s *TCPSource) runConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	s.logger.Debug("received conn", "remote", conn.RemoteAddr())

	if err := s.runConnErr(ctx, conn); err != nil {
		s.logger.Warn("source conn error", "err", err)
	}
}

func (s *TCPSource) runConnErr(ctx context.Context, conn net.Conn) error {
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
