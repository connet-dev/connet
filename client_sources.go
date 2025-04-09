package connet

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"

	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/netc"
)

// SourceTCP creates a new source, and exposes it to a local TCP address to accept incoming traffic
func (c *Client) SourceTCP(ctx context.Context, cfg SourceConfig, addr string) error {
	src, err := c.Source(ctx, cfg)
	if err != nil {
		return err
	}
	go func() {
		tcp := NewTCPSource(src, addr, c.logger)
		if err := tcp.Run(ctx); err != nil {
			c.logger.Info("shutting down source tcp", "err", err)
		}
	}()
	return nil
}

// SourceTLS creates a new source, and exposes it to local TCP address as a TLS server
func (c *Client) SourceTLS(ctx context.Context, cfg SourceConfig, addr string, cert tls.Certificate) error {
	src, err := c.Source(ctx, cfg)
	if err != nil {
		return err
	}
	go func() {
		tcp := NewTLSSource(src, addr, &tls.Config{Certificates: []tls.Certificate{cert}}, c.logger)
		if err := tcp.Run(ctx); err != nil {
			c.logger.Info("shutting down source tcp", "err", err)
		}
	}()
	return nil
}

type Binder func(ctx context.Context) (net.Listener, error)

type TCPSource struct {
	src    Source
	bind   Binder
	logger *slog.Logger
}

func NewTCPSource(src Source, addr string, logger *slog.Logger) *TCPSource {
	return &TCPSource{
		src: src,
		bind: func(ctx context.Context) (net.Listener, error) {
			return net.Listen("tcp", addr)
		},
		logger: logger.With("source", src.Config().Forward, "addr", addr),
	}
}

func NewTLSSource(src Source, addr string, cfg *tls.Config, logger *slog.Logger) *TCPSource {
	return &TCPSource{
		src: src,
		bind: func(ctx context.Context) (net.Listener, error) {
			return tls.Listen("tcp", addr, cfg)
		},
		logger: logger.With("source", src.Config().Forward, "addr", addr),
	}
}

func (s *TCPSource) Run(ctx context.Context) error {
	s.logger.Debug("starting source server")
	l, err := s.bind(ctx)
	if err != nil {
		return fmt.Errorf("source server listen: %w", err)
	}
	defer l.Close()

	go func() {
		<-ctx.Done()
		l.Close()
	}()

	s.logger.Info("listening for conns", "local", l.Addr())
	return (&netc.Joiner{
		Accept: func(ctx context.Context) (net.Conn, error) {
			conn, err := l.Accept()
			s.logger.Debug("source accept", "err", err)
			return conn, err
		},
		Dial: func(ctx context.Context) (net.Conn, error) {
			conn, err := s.src.DialContext(ctx, "", "")
			s.logger.Debug("source dial", "err", err)
			return conn, err
		},
		Join: func(ctx context.Context, acceptConn, dialConn net.Conn) {
			if proxyConn, ok := dialConn.(model.ProxyProtoConn); ok {
				if err := proxyConn.WriteProxyHeader(acceptConn.RemoteAddr(), acceptConn.LocalAddr()); err != nil {
					s.logger.Debug("source write proxy header", "err", err)
					return
				}
			}

			err := netc.Join(ctx, acceptConn, dialConn)
			s.logger.Debug("source disconnected", "err", err)
		},
	}).Run(ctx)
}
