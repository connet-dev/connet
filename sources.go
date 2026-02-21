package connet

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/pkg/netc"
	"github.com/connet-dev/connet/pkg/slogc"
	"github.com/connet-dev/connet/pkg/websocketc"
	"github.com/gorilla/websocket"
)

// SourceTCP creates a new source, and exposes it to a local TCP address to accept incoming traffic
func (c *Client) SourceTCP(ctx context.Context, cfg SourceConfig, addr string) error {
	src, err := c.Source(ctx, cfg)
	if err != nil {
		return err
	}
	go func() {
		srcSrv := NewTCPSource(src, addr, c.logger)
		if err := srcSrv.Run(ctx); err != nil {
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
		srcSrv := NewTLSSource(src, addr, &tls.Config{Certificates: []tls.Certificate{cert}}, c.logger)
		if err := srcSrv.Run(ctx); err != nil {
			c.logger.Info("shutting down source tls", "err", err)
		}
	}()
	return nil
}

// SourceHTTP creates a new source, and exposes it to local TCP address as an HTTP server
func (c *Client) SourceHTTP(ctx context.Context, cfg SourceConfig, srcURL *url.URL) error {
	src, err := c.Source(ctx, cfg)
	if err != nil {
		return err
	}
	go func() {
		srcSrv := NewHTTPSource(src, srcURL, nil)
		if err := srcSrv.Run(ctx); err != nil {
			c.logger.Info("shutting down source http", "err", err)
		}
	}()
	return nil
}

// SourceHTTPS creates a new source, and exposes it to local TCP address as an HTTPS server
func (c *Client) SourceHTTPS(ctx context.Context, cfg SourceConfig, srcURL *url.URL, cert tls.Certificate) error {
	src, err := c.Source(ctx, cfg)
	if err != nil {
		return err
	}
	go func() {
		srcSrv := NewHTTPSource(src, srcURL, &tls.Config{Certificates: []tls.Certificate{cert}})
		if err := srcSrv.Run(ctx); err != nil {
			c.logger.Info("shutting down source https", "err", err)
		}
	}()
	return nil
}

type TCPSource struct {
	src    *Source
	bind   func(ctx context.Context) (net.Listener, error)
	logger *slog.Logger
}

func NewTCPSource(src *Source, addr string, logger *slog.Logger) *TCPSource {
	return &TCPSource{
		src: src,
		bind: func(ctx context.Context) (net.Listener, error) {
			return net.Listen("tcp", addr)
		},
		logger: logger.With("source", src.Config().Endpoint, "addr", addr),
	}
}

func NewTLSSource(src *Source, addr string, cfg *tls.Config, logger *slog.Logger) *TCPSource {
	return &TCPSource{
		src: src,
		bind: func(ctx context.Context) (net.Listener, error) {
			return tls.Listen("tcp", addr, cfg)
		},
		logger: logger.With("source", src.Config().Endpoint, "addr", addr),
	}
}

func (s *TCPSource) Run(ctx context.Context) error {
	s.logger.Debug("starting source server")
	l, err := s.bind(ctx)
	if err != nil {
		return fmt.Errorf("source server listen: %w", err)
	}
	defer func() {
		if err := l.Close(); err != nil {
			slogc.Fine(s.logger, "error defer close listener", "err", err)
		}
	}()

	go func() {
		<-ctx.Done()
		if err := l.Close(); err != nil {
			slogc.Fine(s.logger, "error close listener", "err", err)
		}
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

			err := netc.Join(acceptConn, dialConn)
			s.logger.Debug("source disconnected", "err", err)
		},
	}).Run(ctx)
}

type HTTPSource struct {
	src    *Source
	srcURL *url.URL
	cfg    *tls.Config
}

func NewHTTPSource(src *Source, srcURL *url.URL, cfg *tls.Config) *HTTPSource {
	return &HTTPSource{src, srcURL, cfg}
}

func (s *HTTPSource) Run(ctx context.Context) error {
	endpoint := s.src.Config().Endpoint.String()
	var targetURL = *s.srcURL
	targetURL.Scheme = "http"
	targetURL.Host = endpoint

	srv := &http.Server{
		Addr:      s.srcURL.Host,
		TLSConfig: s.cfg,
		Handler: &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.SetURL(&targetURL)
				pr.SetXForwarded()
			},
			Transport: &http.Transport{
				DialContext: s.src.DialContext,
			},
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				w.WriteHeader(http.StatusBadGateway)
				switch {
				case errors.Is(err, ErrSourceNoActiveDestinations):
					if _, err := fmt.Fprintf(w, "[source %s] no active destinations found", endpoint); err != nil {
						slogc.FineDefault("error writing proxy server error", "err", err)
					}
				case errors.Is(err, ErrSourceConnectDestinations):
					if _, err := fmt.Fprintf(w, "[source %s] cannot dial active destinations", endpoint); err != nil {
						slogc.FineDefault("error writing proxy server error", "err", err)
					}
				default:
					if _, err := fmt.Fprintf(w, "[source %s] %v", endpoint, err); err != nil {
						slogc.FineDefault("error writing proxy server error", "err", err)
					}
				}
			},
		},
	}

	go func() {
		<-ctx.Done()
		if err := srv.Close(); err != nil {
			slogc.FineDefault("error closing source http server", "err", err)
		}
	}()

	if s.cfg != nil {
		return srv.ListenAndServeTLS("", "")
	}
	return srv.ListenAndServe()
}

type WSSource struct {
	src      *Source
	srcURL   *url.URL
	cfg      *tls.Config
	logger   *slog.Logger
	upgrader websocket.Upgrader
}

func NewWSSource(src *Source, srcURL *url.URL, cfg *tls.Config, logger *slog.Logger) *WSSource {
	return &WSSource{
		src, srcURL, cfg, logger, websocket.Upgrader{},
	}
}

func (s *WSSource) handle(w http.ResponseWriter, r *http.Request) {
	hconn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.logger.Debug("could not upgrade connection", "err", err)
		return
	}
	defer func() {
		if err := hconn.Close(); err != nil {
			slogc.Fine(s.logger, "error closing websocket conn", "err", err)
		}
	}()

	sconn, err := s.src.DialContext(r.Context(), "", "")
	if err != nil {
		s.logger.Debug("could not dial destination", "err", err)
		return
	}
	defer func() {
		if err := sconn.Close(); err != nil {
			slogc.Fine(s.logger, "error closing source conn", "err", err)
		}
	}()

	err = websocketc.Join(sconn, hconn)
	s.logger.Debug("completed websocket connection", "err", err)
}

func (s *WSSource) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	path := s.srcURL.Path
	if path == "" {
		path = "/"
	}
	mux.HandleFunc(path, s.handle)

	srv := &http.Server{
		Addr:      s.srcURL.Host,
		TLSConfig: s.cfg,
		Handler:   mux,
	}

	go func() {
		<-ctx.Done()
		if err := srv.Close(); err != nil {
			slogc.FineDefault("error closing source ws server", "err", err)
		}
	}()

	if s.cfg != nil {
		return srv.ListenAndServeTLS("", "")
	}
	return srv.ListenAndServe()
}
