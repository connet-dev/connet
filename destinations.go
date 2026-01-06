package connet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/connet-dev/connet/pkg/netc"
	"github.com/connet-dev/connet/pkg/slogc"
)

// DestinationTCP creates a new destination which connects to a downstream TCP server
func (c *Client) DestinationTCP(ctx context.Context, cfg DestinationConfig, addr string) error {
	dst, err := c.Destination(ctx, cfg)
	if err != nil {
		return err
	}
	go func() {
		dstSrv := NewTCPDestination(dst, addr, cfg.DialTimeout, c.logger)
		if err := dstSrv.Run(ctx); err != nil {
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
	go func() {
		dstSrv := NewTLSDestination(dst, addr, &tls.Config{RootCAs: cas}, cfg.DialTimeout, c.logger)
		if err := dstSrv.Run(ctx); err != nil {
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
	go func() {
		dstSrv := NewHTTPDestination(dst, handler)
		if err := dstSrv.Run(ctx); err != nil {
			c.logger.Info("shutting down destination http", "err", err)
		}
	}()
	return nil
}

// DestinationHTTPProxy creates a new destination which exposes an HTTP proxy server to another HTTP server
func (c *Client) DestinationHTTPProxy(ctx context.Context, cfg DestinationConfig, dstUrl *url.URL) error {
	dst, err := c.Destination(ctx, cfg)
	if err != nil {
		return err
	}
	go func() {
		dstSrv := NewHTTPProxyDestination(dst, dstUrl, nil, cfg.DialTimeout)
		if err := dstSrv.Run(ctx); err != nil {
			c.logger.Info("shutting down destination http", "err", err)
		}
	}()
	return nil
}

// DestinationHTTPSProxy creates a new destination which exposes an HTTP proxy server to another HTTPS server
func (c *Client) DestinationHTTPSProxy(ctx context.Context, cfg DestinationConfig, dstUrl *url.URL, cas *x509.CertPool) error {
	dst, err := c.Destination(ctx, cfg)
	if err != nil {
		return err
	}
	go func() {
		dstSrv := NewHTTPProxyDestination(dst, dstUrl, &tls.Config{RootCAs: cas}, cfg.DialTimeout)
		if err := dstSrv.Run(ctx); err != nil {
			c.logger.Info("shutting down destination http", "err", err)
		}
	}()
	return nil
}

type dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type TCPDestination struct {
	dst    *Destination
	dialer dialer
	addr   string
	logger *slog.Logger
}

func newTCPDestination(dst *Destination, d dialer, addr string, logger *slog.Logger) *TCPDestination {
	return &TCPDestination{
		dst:    dst,
		addr:   addr,
		dialer: d,
		logger: logger.With("destination", dst.Config().Endpoint, "addr", addr),
	}
}

func NewTCPDestination(dst *Destination, addr string, timeout time.Duration, logger *slog.Logger) *TCPDestination {
	return newTCPDestination(dst, &net.Dialer{Timeout: timeout}, addr, logger)
}

func NewTLSDestination(dst *Destination, addr string, cfg *tls.Config, timeout time.Duration, logger *slog.Logger) *TCPDestination {
	return newTCPDestination(dst, &tls.Dialer{NetDialer: &net.Dialer{Timeout: timeout}, Config: cfg}, addr, logger)
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
			err := netc.Join(acceptConn, dialConn)
			d.logger.Debug("destination disconnected", "err", err)
		},
	}).Run(ctx)
}

type HTTPDestination struct {
	dst *Destination

	handler http.Handler
}

func NewHTTPDestination(dst *Destination, handler http.Handler) *HTTPDestination {
	return &HTTPDestination{dst, handler}
}

func NewHTTPFileDestination(dst *Destination, root string) *HTTPDestination {
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir(root)))
	return NewHTTPDestination(dst, mux)
}

func NewHTTPProxyDestination(dst *Destination, dstURL *url.URL, cfg *tls.Config, timeout time.Duration) *HTTPDestination {
	return NewHTTPDestination(dst, &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(dstURL)
			pr.SetXForwarded()
		},
		Transport: &http.Transport{
			TLSClientConfig: cfg,
			DialContext: (&net.Dialer{
				Timeout:   timeout,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		},
	})
}

func (d *HTTPDestination) Run(ctx context.Context) error {
	srv := &http.Server{
		Handler: d.handler,
	}

	go func() {
		<-ctx.Done()
		if err := srv.Close(); err != nil {
			slogc.FineDefault("error closing destination http server", "err", err)
		}
	}()

	return srv.Serve(d.dst)
}
