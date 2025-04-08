package connet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"
	"net/http"

	"github.com/connet-dev/connet/netc"
)

// DestinationTCP creates a new destination which connects to a downstream TCP server
func (c *Client) DestinationTCP(ctx context.Context, cfg DestinationConfig, addr string) error {
	dst, err := c.Destination(ctx, cfg)
	if err != nil {
		return err
	}
	tcp := NewTCPDestination(dst, addr, c.logger)
	go func() {
		if err := tcp.Run(ctx); err != nil {
			c.logger.Info("shutting down destination tcp", "err", err)
		}
	}()
	return nil
}

// DestinationTLS creates a new destination which connects to a downstream TLS server
func (c *Client) DestinationTLS(ctx context.Context, cfg DestinationConfig, addr string, cas *x509.CertPool) error {
	dst, err := c.Destination(ctx, cfg)
	if err != nil {
		return err
	}
	tls := NewTLSDestination(dst, addr, &tls.Config{RootCAs: cas}, c.logger)
	go func() {
		if err := tls.Run(ctx); err != nil {
			c.logger.Info("shutting down destination tls", "err", err)
		}
	}()
	return nil
}

// DestinationHTTP creates a new destination which exposes an HTTP server for a given [http.Handler]
func (c *Client) DestinationHTTP(ctx context.Context, cfg DestinationConfig, handler http.Handler) error {
	dst, err := c.Destination(ctx, cfg)
	if err != nil {
		return err
	}
	htp := NewHTTPDestination(dst, handler)
	go func() {
		if err := htp.Run(ctx); err != nil {
			c.logger.Info("shutting down destination http", "err", err)
		}
	}()
	return nil
}

type dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type TCPDestination struct {
	dst    Destination
	dialer dialer
	addr   string
	logger *slog.Logger
}

func newTCPDestination(dst Destination, d dialer, addr string, logger *slog.Logger) *TCPDestination {
	return &TCPDestination{
		dst:    dst,
		addr:   addr,
		dialer: d,
		logger: logger.With("destination", dst.Config().Forward, "addr", addr),
	}
}

func NewTCPDestination(dst Destination, addr string, logger *slog.Logger) *TCPDestination {
	return newTCPDestination(dst, &net.Dialer{}, addr, logger)
}

func NewTLSDestination(dst Destination, addr string, cfg *tls.Config, logger *slog.Logger) *TCPDestination {
	return newTCPDestination(dst, &tls.Dialer{NetDialer: &net.Dialer{}, Config: cfg}, addr, logger)
}

func (d *TCPDestination) Run(ctx context.Context) error {
	return (&netc.Joiner{
		Accept: func(ctx context.Context) (net.Conn, error) {
			conn, err := d.dst.AcceptContext(ctx)
			d.logger.Debug("destination accept", "err", err)
			return conn, err
		},
		Dial: func(ctx context.Context) (net.Conn, error) {
			conn, err := d.dialer.DialContext(ctx, "tcp", d.addr)
			d.logger.Debug("destination dial", "err", err)
			return conn, err
		},
		Join: func(ctx context.Context, acceptConn, dialConn net.Conn) {
			err := netc.Join(ctx, acceptConn, dialConn)
			d.logger.Debug("destination disconnected", "err", err)
		},
	}).Run(ctx)
}

type HTTPDestination struct {
	dst     Destination
	handler http.Handler
}

func NewHTTPDestination(dst Destination, handler http.Handler) *HTTPDestination {
	return &HTTPDestination{dst, handler}
}

func NewHTTPFileDestination(dst Destination, root string) *HTTPDestination {
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
