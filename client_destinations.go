package connet

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"

	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/netc"
)

func (c *Client) DestinationTCP(ctx context.Context, cfg DestinationConfig, addr string) error {
	dst, err := c.Destination(ctx, cfg)
	if err != nil {
		return err
	}
	tcp, err := NewTCPDestination(dst, cfg.Forward, addr, c.logger)
	if err != nil {
		return err
	}
	go func() {
		if err := tcp.Run(ctx); err != nil {
			c.logger.Info("shutting down destination tcp", "err", err)
		}
	}()
	return nil
}

func (c *Client) DestinationHTTP(ctx context.Context, cfg DestinationConfig, handler http.Handler) error {
	dst, err := c.Destination(ctx, cfg)
	if err != nil {
		return err
	}
	htp, err := NewHTTPDestination(dst, handler)
	if err != nil {
		return err
	}
	go func() {
		if err := htp.Run(ctx); err != nil {
			c.logger.Info("shutting down destination http", "err", err)
		}
	}()
	return nil
}

type TCPDestination struct {
	dst    Destination
	addr   string
	logger *slog.Logger
}

func NewTCPDestination(dst Destination, fwd model.Forward, addr string, logger *slog.Logger) (*TCPDestination, error) {
	return &TCPDestination{
		dst:    dst,
		addr:   addr,
		logger: logger.With("destination", fwd, "addr", addr),
	}, nil
}

func (d *TCPDestination) Run(ctx context.Context) error {
	for {
		conn, err := d.dst.AcceptContext(ctx)
		if err != nil {
			return err
		}
		go d.runConn(ctx, conn)
	}
}

func (d *TCPDestination) runConn(ctx context.Context, remoteConn net.Conn) {
	defer remoteConn.Close()

	if err := d.runConnErr(ctx, remoteConn); err != nil {
		d.logger.Warn("destination conn error", "err", err)
	}
}

func (d *TCPDestination) runConnErr(ctx context.Context, remoteConn net.Conn) error {
	conn, err := net.Dial("tcp", d.addr)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	err = netc.Join(ctx, remoteConn, conn)
	d.logger.Debug("disconnected conns", "err", err)

	return nil
}

type HTTPDestination struct {
	dst     Destination
	handler http.Handler
}

func NewHTTPDestination(dst Destination, handler http.Handler) (*HTTPDestination, error) {
	return &HTTPDestination{dst, handler}, nil
}

func NewHTTPFileDestination(dst Destination, root string) (*HTTPDestination, error) {
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir(root)))
	return NewHTTPDestination(dst, mux)
}

func (d *HTTPDestination) Run(ctx context.Context) error {
	srv := &http.Server{
		Handler: d.handler,
	}

	go func() {
		<-ctx.Done()
		srv.Close()
	}()

	return srv.Serve(d.dst)
}
