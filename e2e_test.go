package connet

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/connet-dev/connet/certc"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/restr"
	"github.com/connet-dev/connet/selfhosted"
	"github.com/connet-dev/connet/statusc"
	"github.com/pires/go-proxyproto"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

type connectedTestCase struct {
	d     DestinationConfig
	s     SourceConfig
	sport int
}

func (tc connectedTestCase) isSuccess() bool {
	return tc.sport >= 10000 && tc.sport < 10100
}

func (tc connectedTestCase) isFail() bool {
	return tc.sport >= 10100 && tc.sport < 10200
}

func (tc connectedTestCase) isSuccessProxyProto() bool {
	return tc.sport >= 10200 && tc.sport < 10300
}

func (tc connectedTestCase) isSuccessTLS() bool {
	return tc.sport >= 10300 && tc.sport < 10400
}

var connectedTests = map[string]connectedTestCase{
	// 100XX are succesful tests
	"direct": {
		NewDestinationConfig("direct").WithRoute(model.RouteDirect),
		NewSourceConfig("direct").WithRoute(model.RouteDirect),
		10000,
	},
	"relay": {
		NewDestinationConfig("relay").WithRoute(model.RouteRelay),
		NewSourceConfig("relay").WithRoute(model.RouteRelay),
		10001,
	},
	"dst-any-direct-src": {
		NewDestinationConfig("dst-any-direct-src"),
		NewSourceConfig("dst-any-direct-src").WithRoute(model.RouteDirect),
		10002,
	},
	"dst-any-relay-src": {
		NewDestinationConfig("dst-any-relay-src"),
		NewSourceConfig("dst-any-relay-src").WithRoute(model.RouteRelay),
		10003,
	},
	"dst-direct-any-src": {
		NewDestinationConfig("dst-direct-any-src").WithRoute(model.RouteDirect),
		NewSourceConfig("dst-direct-any-src").WithRoute(model.RouteAny),
		10004,
	},
	"dst-relay-any-src": {
		NewDestinationConfig("dst-relay-any-src").WithRoute(model.RouteRelay),
		NewSourceConfig("dst-relay-any-src").WithRoute(model.RouteAny),
		10005,
	},
	"relay-tls-encrypted": {
		NewDestinationConfig("relay-tls-encrypted").WithRoute(model.RouteRelay).WithRelayEncryptions(model.TLSEncryption),
		NewSourceConfig("relay-tls-encrypted").WithRoute(model.RouteRelay).WithRelayEncryptions(model.TLSEncryption),
		10006,
	},
	"relay-dhxcp-encrypted": {
		NewDestinationConfig("relay-dhxcp-encrypted").WithRoute(model.RouteRelay).WithRelayEncryptions(model.DHXCPEncryption),
		NewSourceConfig("relay-dhxcp-encrypted").WithRoute(model.RouteRelay).WithRelayEncryptions(model.DHXCPEncryption),
		10007,
	},
	// 101XX fail to dial
	"dst-direct-relay-src": {
		NewDestinationConfig("dst-direct-relay-src").WithRoute(model.RouteDirect),
		NewSourceConfig("dst-direct-relay-src").WithRoute(model.RouteRelay),
		10100,
	},
	"dst-relay-direct-src": {
		NewDestinationConfig("dst-relay-direct-src").WithRoute(model.RouteRelay),
		NewSourceConfig("dst-relay-direct-src").WithRoute(model.RouteDirect),
		10101,
	},
	"relay-dst-none-tls-src": {
		NewDestinationConfig("relay-dst-none-tls-src").WithRoute(model.RouteRelay).WithRelayEncryptions(model.NoEncryption),
		NewSourceConfig("relay-dst-none-tls-src").WithRoute(model.RouteRelay).WithRelayEncryptions(model.TLSEncryption),
		10102,
	},
	"relay-dst-tls-none-src": {
		NewDestinationConfig("relay-dst-tls-none-src").WithRoute(model.RouteRelay).WithRelayEncryptions(model.TLSEncryption),
		NewSourceConfig("relay-dst-tls-none-src").WithRoute(model.RouteRelay).WithRelayEncryptions(model.NoEncryption),
		10103,
	},
	// 102XX expose proxy proto server
	"dst-direct-proxy-proto": {
		NewDestinationConfig("dst-direct-proxy-proto").WithRoute(model.RouteDirect).WithProxy(model.ProxyV1),
		NewSourceConfig("dst-direct-proxy-proto").WithRoute(model.RouteAny),
		10200,
	},
	"dst-relay-proxy-proto": {
		NewDestinationConfig("dst-relay-proxy-proto").WithRoute(model.RouteRelay).WithProxy(model.ProxyV2),
		NewSourceConfig("dst-relay-proxy-proto").WithRoute(model.RouteAny),
		10201,
	},
	// 103XX expose HTTPS server
	"direct-tls": {
		NewDestinationConfig("direct-tls").WithRoute(model.RouteDirect),
		NewSourceConfig("direct-tls").WithRoute(model.RouteDirect),
		10300,
	},
	"relay-tls": {
		NewDestinationConfig("relay-tls").WithRoute(model.RouteRelay),
		NewSourceConfig("relay-tls").WithRoute(model.RouteRelay),
		10301,
	},
}

func TestE2E(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cert, cas, err := certc.SelfSigned("localhost")
	require.NoError(t, err)

	htServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello:%s", r.URL.Query().Get("rand"))
	}))
	htAddr := htServer.Listener.Addr().String()
	defer htServer.Close()

	htsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello:%s", r.URL.Query().Get("rand"))
	}))
	htsAddr := htsServer.Listener.Addr().String()
	defer htsServer.Close()

	ppListen, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ppAddr := ppListen.Addr().String()
	defer ppListen.Close()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	localRestr, err := restr.ParseIP([]string{"192.0.2.0/24"}, nil)
	require.NoError(t, err)
	tetRestr, err := restr.ParseName("^tet$")
	require.NoError(t, err)
	clientAuth := selfhosted.NewClientAuthenticator(
		selfhosted.ClientAuthentication{Token: "test-token-dst"},
		selfhosted.ClientAuthentication{Token: "test-token-src"},
		selfhosted.ClientAuthentication{Token: "test-token-deny-ip", IPs: localRestr},
		selfhosted.ClientAuthentication{Token: "test-token-deny-name", Names: tetRestr},
		selfhosted.ClientAuthentication{Token: "test-token-deny-role", Role: model.Source},
	)

	srv, err := NewServer(
		ServerClientAuthenticator(clientAuth),
		serverCertificate(cert),
		ServerClientsAddress(":20000"),
		ServerRelayAddress(":20001"),
		ServerLogger(logger.With("test", "server")),
	)
	require.NoError(t, err)

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error { return proxyProtoServer(ctx, ppListen) })
	g.Go(func() error { return srv.Run(ctx) })

	time.Sleep(time.Millisecond) // time for server to come online

	t.Run("deny-ip", func(t *testing.T) {
		clIPDeny, err := Connect(ctx,
			ClientToken("test-token-deny-ip"),
			ClientControlAddress("localhost:20000"),
			clientControlCAs(cas),
			ClientDirectAddress(":20002"),
			ClientLogger(logger.With("test", "cl-ip-deny")),
		)
		require.ErrorContains(t, err, "address not allowed")
		require.Nil(t, clIPDeny)
	})
	t.Run("deny-name", func(t *testing.T) {
		clNameDeny, err := Connect(ctx,
			ClientToken("test-token-deny-name"),
			ClientControlAddress("localhost:20000"),
			clientControlCAs(cas),
			ClientDirectAddress(":20002"),
			ClientLogger(logger.With("test", "cl-name-deny")),
		)
		require.NoError(t, err)
		defer clNameDeny.Close()

		dst, err := clNameDeny.Destination(ctx, NewDestinationConfig("direct"))
		require.ErrorContains(t, err, "forward not allowed")
		require.Nil(t, dst)
	})
	t.Run("deny-role", func(t *testing.T) {
		clRoleDeny, err := Connect(ctx,
			ClientToken("test-token-deny-role"),
			ClientControlAddress("localhost:20000"),
			clientControlCAs(cas),
			ClientDirectAddress(":20003"),
			ClientLogger(logger.With("test", "cl-role-deny")),
		)
		require.NoError(t, err)
		defer clRoleDeny.Close()

		dst, err := clRoleDeny.Destination(ctx, NewDestinationConfig("direct"))
		require.ErrorContains(t, err, "role not allowed")
		require.Nil(t, dst)
	})
	t.Run("close-client", func(t *testing.T) {
		cl, err := Connect(ctx,
			ClientToken("test-token-dst"),
			ClientControlAddress("localhost:20000"),
			clientControlCAs(cas),
			ClientDirectAddress(":20002"),
			ClientLogger(logger.With("test", "cl-dst")),
		)
		require.NoError(t, err)
		require.NotNil(t, cl)

		dst, err := cl.Destination(ctx, NewDestinationConfig("closing"))
		require.NoError(t, err)
		defer dst.Close()

		src, err := cl.Source(ctx, NewSourceConfig("closing"))
		require.NoError(t, err)
		defer src.Close()

		require.NoError(t, cl.Close())
		require.Empty(t, cl.Destinations())
		require.Empty(t, cl.Sources())

		var acceptConn, dialConn net.Conn
		var acceptErr, dialErr error
		var acceptCh, dialCh = make(chan struct{}), make(chan struct{})
		go func() {
			acceptConn, acceptErr = dst.Accept()
			close(acceptCh)
		}()
		go func() {
			dialConn, dialErr = src.Dial("", "")
			close(dialCh)
		}()

		<-acceptCh
		<-dialCh

		require.ErrorIs(t, acceptErr, net.ErrClosed)
		require.ErrorIs(t, dialErr, ErrNoActiveDestinations)
		require.Nil(t, acceptConn)
		require.Nil(t, dialConn)
	})
	t.Run("cancel-client", func(t *testing.T) {
		clCtx, clCancel := context.WithCancel(ctx)
		cl, err := Connect(clCtx,
			ClientToken("test-token-dst"),
			ClientControlAddress("localhost:20000"),
			clientControlCAs(cas),
			ClientDirectAddress(":20002"),
			ClientLogger(logger.With("test", "cl-dst")),
		)
		require.NoError(t, err)
		require.NotNil(t, cl)

		dst, err := cl.Destination(ctx, NewDestinationConfig("closing"))
		require.NoError(t, err)
		defer dst.Close()

		src, err := cl.Source(ctx, NewSourceConfig("closing"))
		require.NoError(t, err)
		defer src.Close()

		clCancel()
		for {
			time.Sleep(time.Millisecond)
			stat, err := cl.Status(ctx)
			require.NoError(t, err)
			if stat.Status == statusc.Disconnected {
				break
			}
		}
		require.Empty(t, cl.Destinations())
		require.Empty(t, cl.Sources())

		var acceptConn, dialConn net.Conn
		var acceptErr, dialErr error
		var acceptCh, dialCh = make(chan struct{}), make(chan struct{})
		go func() {
			acceptConn, acceptErr = dst.Accept()
			close(acceptCh)
		}()
		go func() {
			dialConn, dialErr = src.Dial("", "")
			close(dialCh)
		}()

		<-acceptCh
		<-dialCh

		require.ErrorIs(t, acceptErr, net.ErrClosed)
		require.ErrorIs(t, dialErr, ErrNoActiveDestinations)
		require.Nil(t, acceptConn)
		require.Nil(t, dialConn)
	})
	t.Run("close-dst", func(t *testing.T) {
		cl, err := Connect(ctx,
			ClientToken("test-token-dst"),
			ClientControlAddress("localhost:20000"),
			clientControlCAs(cas),
			ClientDirectAddress(":20002"),
			ClientLogger(logger.With("test", "cl-dst")),
		)
		require.NoError(t, err)
		defer cl.Close()

		dst, err := cl.Destination(ctx, NewDestinationConfig("closing"))
		require.NoError(t, err)
		require.NoError(t, dst.Close())

		require.Empty(t, cl.Destinations())
	})
	t.Run("cancel-dst", func(t *testing.T) {
		cl, err := Connect(ctx,
			ClientToken("test-token-dst"),
			ClientControlAddress("localhost:20000"),
			clientControlCAs(cas),
			ClientDirectAddress(":20002"),
			ClientLogger(logger.With("test", "cl-dst")),
		)
		require.NoError(t, err)
		defer cl.Close()

		dstCtx, dstCancel := context.WithCancel(ctx)
		dst, err := cl.Destination(dstCtx, NewDestinationConfig("closing"))
		require.NoError(t, err)
		dstCancel()

		for {
			time.Sleep(time.Millisecond)
			stat, err := dst.Status(ctx)
			require.NoError(t, err)
			if stat.Status == statusc.Disconnected {
				break
			}
		}
		require.Empty(t, cl.Destinations())
	})

	clDst, err := Connect(ctx,
		ClientToken("test-token-dst"),
		ClientControlAddress("localhost:20000"),
		clientControlCAs(cas),
		ClientDirectAddress(":20002"),
		ClientLogger(logger.With("test", "cl-dst")),
	)
	require.NoError(t, err)

	clSrc, err := Connect(ctx,
		ClientToken("test-token-src"),
		ClientControlAddress("localhost:20000"),
		clientControlCAs(cas),
		ClientDirectAddress(":20003"),
		ClientLogger(logger.With("test", "cl-src")),
	)
	require.NoError(t, err)

	for name, tc := range connectedTests {
		require.Equal(t, name, tc.d.Forward.String())
		require.Equal(t, name, tc.s.Forward.String())

		dst, err := clDst.Destination(ctx, tc.d)
		require.NoError(t, err)

		switch {
		case strings.HasSuffix(name, "-proxy-proto"):
			dstSrv := NewTCPDestination(dst, ppAddr, logger)
			g.Go(func() error { return dstSrv.Run(ctx) })
		case strings.HasSuffix(name, "-tls"):
			clientTransport := htsServer.Client().Transport.(*http.Transport)
			dstSrv := NewTLSDestination(dst, htsAddr, clientTransport.TLSClientConfig, logger)
			g.Go(func() error { return dstSrv.Run(ctx) })
		default:
			dstSrv := NewTCPDestination(dst, htAddr, logger)
			g.Go(func() error { return dstSrv.Run(ctx) })
		}

		src, err := clSrc.Source(ctx, tc.s)
		require.NoError(t, err)

		switch {
		case strings.HasSuffix(name, "-tls"):
			srcSrv := NewTLSSource(src, fmt.Sprintf(":%d", tc.sport), htsServer.TLS, logger)
			g.Go(func() error { return srcSrv.Run(ctx) })
		default:
			srcSrv := NewTCPSource(src, fmt.Sprintf(":%d", tc.sport), logger)
			g.Go(func() error { return srcSrv.Run(ctx) })
		}
	}

	require.ElementsMatch(t, slices.Collect(maps.Keys(connectedTests)), clDst.Destinations())
	require.ElementsMatch(t, slices.Collect(maps.Keys(connectedTests)), clSrc.Sources())

	time.Sleep(100 * time.Millisecond) // time for clients to come online

	// actual test
	httpcl := &http.Client{}
	httpcl.Transport = &http.Transport{DisableKeepAlives: true}

	// Positive
	// ports := slices.Repeat([]int{10000, 10001, 10002, 10003, 10004, 10005, 10006, 10007}, 3)
	for i := range 3 {
		t.Run(fmt.Sprintf("success-%d", i), func(t *testing.T) {
			for name, tc := range connectedTests {
				if tc.isSuccess() {
					t.Run(name, func(t *testing.T) {
						rnd := rand.Uint64()
						url := fmt.Sprintf("http://127.0.0.1:%d?rand=%d", tc.sport, rnd)

						resp, err := httpcl.Get(url)
						require.NoError(t, err)
						defer resp.Body.Close()

						respData, err := io.ReadAll(resp.Body)
						require.NoError(t, err)

						require.Equal(t, fmt.Sprintf("hello:%d", rnd), string(respData))
					})
				}
			}
		})
	}

	// Negative
	t.Run("negative", func(t *testing.T) {
		for name, tc := range connectedTests {
			if tc.isFail() {
				t.Run(name, func(t *testing.T) {
					rnd := rand.Uint64()
					url := fmt.Sprintf("http://127.0.0.1:%d?rand=%d", tc.sport, rnd)

					// TODO better use HTTP source to report errors
					_, err := httpcl.Get(url)
					require.Error(t, err)
					switch {
					case errors.Is(err, syscall.ECONNRESET):
					case errors.Is(err, io.EOF):
					default:
						require.ErrorContains(t, err, "connection reset by peer")
					}
				})
			}
		}
	})

	// specialized
	t.Run("success-proxy-proto", func(t *testing.T) {
		for name, tc := range connectedTests {
			if tc.isSuccessProxyProto() {
				t.Run(name, func(t *testing.T) {
					expectedVersion := byte(1)
					if name == "dst-relay-proxy-proto" {
						expectedVersion = byte(2)
					}
					conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tc.sport))
					require.NoError(t, err)
					defer conn.Close()

					_, err = conn.Write([]byte("abc\n"))
					require.NoError(t, err)

					buf := bufio.NewReader(conn)
					hdr, err := proxyproto.Read(buf)
					require.NoError(t, err)
					require.NotNil(t, hdr)
					require.Equal(t, expectedVersion, hdr.Version)
					require.Equal(t, conn.LocalAddr(), hdr.SourceAddr)
					require.Equal(t, conn.RemoteAddr(), hdr.DestinationAddr)

					rest, err := buf.ReadBytes('\n')
					require.NoError(t, err)
					require.Equal(t, "abc\n", string(rest))
				})
			}
		}
	})

	t.Run("success-tls", func(t *testing.T) {
		for name, tc := range connectedTests {
			if tc.isSuccessTLS() {
				t.Run(name, func(t *testing.T) {
					rnd := rand.Uint64()
					url := fmt.Sprintf("https://127.0.0.1:%d?rand=%d", tc.sport, rnd)

					resp, err := htsServer.Client().Get(url)
					require.NoError(t, err)
					defer resp.Body.Close()

					respData, err := io.ReadAll(resp.Body)
					require.NoError(t, err)

					require.Equal(t, fmt.Sprintf("hello:%d", rnd), string(respData))
				})
			}
		}
	})

	cancel()

	// make sure everything shuts down on context cancel
	_ = g.Wait()
}

func serverCertificate(cert tls.Certificate) ServerOption {
	return func(cfg *serverConfig) error {
		cfg.cert = cert

		return nil
	}
}

func proxyProtoServer(ctx context.Context, l net.Listener) error {
	go func() {
		<-ctx.Done()
		l.Close()
	}()
	for {
		conn, err := l.Accept()
		if err != nil {
			return nil
		}
		defer conn.Close()

		buf := bufio.NewReader(conn)
		if hdr, err := proxyproto.Read(buf); err != nil {
			return err
		} else if _, err := hdr.WriteTo(conn); err != nil {
			return err
		}

		if b, err := buf.ReadBytes('\n'); err != nil {
			return err
		} else if _, err := conn.Write(b); err != nil {
			return err
		}
	}
}

func clientControlCAs(cas *x509.CertPool) ClientOption {
	return func(cfg *clientConfig) error {
		cfg.controlCAs = cas

		return nil
	}
}
