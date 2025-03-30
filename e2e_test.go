package connet

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/connet-dev/connet/certc"
	"github.com/connet-dev/connet/client"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/restr"
	"github.com/connet-dev/connet/selfhosted"
	"github.com/pires/go-proxyproto"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func TestE2E(t *testing.T) {
	cert, cas, err := certc.SelfSigned("localhost")
	require.NoError(t, err)

	hts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello:%s", r.URL.Query().Get("rand"))
	}))
	htAddr := hts.Listener.Addr().String()
	defer hts.Close()

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

	clDst, err := NewClient(
		ClientToken("test-token-dst"),
		ClientControlAddress("localhost:20000"),
		clientControlCAs(cas),
		ClientDirectAddress(":20002"),
		ClientDestination(client.NewDestinationConfig("direct", htAddr).WithRoute(model.RouteDirect)),
		ClientDestination(client.NewDestinationConfig("relay", htAddr).WithRoute(model.RouteRelay)),
		ClientDestination(client.NewDestinationConfig("dst-any-direct-src", htAddr)),
		ClientDestination(client.NewDestinationConfig("dst-any-relay-src", htAddr)),
		ClientDestination(client.NewDestinationConfig("dst-direct-any-src", htAddr).WithRoute(model.RouteDirect)),
		ClientDestination(client.NewDestinationConfig("dst-relay-any-src", htAddr).WithRoute(model.RouteRelay)),
		ClientDestination(client.NewDestinationConfig("relay-tls", htAddr).WithRoute(model.RouteRelay).WithRelayEncryptions(model.TLSEncryption)),
		ClientDestination(client.NewDestinationConfig("relay-ecdh", htAddr).WithRoute(model.RouteRelay).WithRelayEncryptions(model.ECDHEncryption)),

		ClientDestination(client.NewDestinationConfig("dst-direct-relay-src", htAddr).WithRoute(model.RouteDirect)),
		ClientDestination(client.NewDestinationConfig("dst-relay-direct-src", htAddr).WithRoute(model.RouteRelay)),
		ClientDestination(client.NewDestinationConfig("relay-dst-none-tls-src", htAddr).WithRoute(model.RouteRelay).WithRelayEncryptions(model.NoEncryption)),
		ClientDestination(client.NewDestinationConfig("relay-dst-tls-none-src", htAddr).WithRoute(model.RouteRelay).WithRelayEncryptions(model.TLSEncryption)),

		ClientDestination(client.NewDestinationConfig("dst-direct-proxy-proto", ppAddr).WithRoute(model.RouteDirect).WithProxy(model.ProxyV1)),
		ClientDestination(client.NewDestinationConfig("dst-relay-proxy-proto", ppAddr).WithRoute(model.RouteRelay).WithProxy(model.ProxyV2)),

		ClientLogger(logger.With("test", "cl-dst")),
	)
	require.NoError(t, err)

	clSrc, err := NewClient(
		ClientToken("test-token-src"),
		ClientControlAddress("localhost:20000"),
		clientControlCAs(cas),
		ClientDirectAddress(":20003"),
		ClientSource(client.NewSourceConfig("direct", ":10000").WithRoute(model.RouteDirect)),
		ClientSource(client.NewSourceConfig("relay", ":10001").WithRoute(model.RouteRelay)),
		ClientSource(client.NewSourceConfig("dst-any-direct-src", ":10002").WithRoute(model.RouteDirect)),
		ClientSource(client.NewSourceConfig("dst-any-relay-src", ":10003").WithRoute(model.RouteRelay)),
		ClientSource(client.NewSourceConfig("dst-direct-any-src", ":10004").WithRoute(model.RouteAny)),
		ClientSource(client.NewSourceConfig("dst-relay-any-src", ":10005").WithRoute(model.RouteAny)),
		ClientSource(client.NewSourceConfig("relay-tls", ":10006").WithRoute(model.RouteRelay).WithRelayEncryptions(model.TLSEncryption)),
		ClientSource(client.NewSourceConfig("relay-ecdh", ":10007").WithRoute(model.RouteRelay).WithRelayEncryptions(model.ECDHEncryption)),

		ClientSource(client.NewSourceConfig("dst-direct-relay-src", ":10100").WithRoute(model.RouteRelay)),
		ClientSource(client.NewSourceConfig("dst-relay-direct-src", ":10101").WithRoute(model.RouteDirect)),
		ClientSource(client.NewSourceConfig("relay-dst-tls-none-src", ":10102").WithRoute(model.RouteRelay).WithRelayEncryptions(model.NoEncryption)),
		ClientSource(client.NewSourceConfig("relay-dst-none-tls-src", ":10103").WithRoute(model.RouteRelay).WithRelayEncryptions(model.TLSEncryption)),

		ClientSource(client.NewSourceConfig("dst-direct-proxy-proto", ":10200").WithRoute(model.RouteAny)),
		ClientSource(client.NewSourceConfig("dst-relay-proxy-proto", ":10201").WithRoute(model.RouteAny)),

		ClientLogger(logger.With("test", "cl-src")),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error { return proxyProtoServer(ctx, ppListen) })
	g.Go(func() error { return srv.Run(ctx) })
	time.Sleep(time.Millisecond) // time for server to come online

	t.Run("deny-ip", func(t *testing.T) {
		clIPDeny, err := NewClient(
			ClientToken("test-token-deny-ip"),
			ClientControlAddress("localhost:20000"),
			clientControlCAs(cas),
			ClientDirectAddress(":20003"),
			ClientDestination(client.NewDestinationConfig("direct", htAddr)),
			ClientLogger(logger.With("test", "cl-ip-deny")),
		)
		require.NoError(t, err)

		require.ErrorContains(t, clIPDeny.Run(ctx), "address not allowed")
	})
	t.Run("deny-name", func(t *testing.T) {
		clNameDeny, err := NewClient(
			ClientToken("test-token-deny-name"),
			ClientControlAddress("localhost:20000"),
			clientControlCAs(cas),
			ClientDirectAddress(":20004"),
			ClientDestination(client.NewDestinationConfig("direct", htAddr)),
			ClientLogger(logger.With("test", "cl-name-deny")),
		)
		require.NoError(t, err)

		require.ErrorContains(t, clNameDeny.Run(ctx), "forward not allowed")
	})
	t.Run("deny-role", func(t *testing.T) {
		clNameDeny, err := NewClient(
			ClientToken("test-token-deny-role"),
			ClientControlAddress("localhost:20000"),
			clientControlCAs(cas),
			ClientDirectAddress(":20005"),
			ClientDestination(client.NewDestinationConfig("direct", htAddr)),
			ClientLogger(logger.With("test", "cl-role-deny")),
		)
		require.NoError(t, err)

		require.ErrorContains(t, clNameDeny.Run(ctx), "role not allowed")
	})

	g.Go(func() error { return clDst.Run(ctx) })
	g.Go(func() error { return clSrc.Run(ctx) })
	time.Sleep(500 * time.Millisecond) // time for clients to come online

	// actual test
	httpcl := &http.Client{}
	httpcl.Transport = &http.Transport{DisableKeepAlives: true}

	// Positive
	ports := slices.Repeat([]int{10000, 10001, 10002, 10003, 10004, 10005, 10006, 10007}, 3)
	for i, port := range ports {
		t.Run(fmt.Sprintf("success-%d:%d", i, port), func(t *testing.T) {
			rnd := rand.Uint64()
			url := fmt.Sprintf("http://localhost:%d?rand=%d", port, rnd)

			resp, err := httpcl.Get(url)
			require.NoError(t, err)
			defer resp.Body.Close()

			respData, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			require.Equal(t, fmt.Sprintf("hello:%d", rnd), string(respData))
		})
	}

	for i, port := range []int{10100, 10101, 10102, 10103} {
		t.Run(fmt.Sprintf("failing-%d:%d", i, port), func(t *testing.T) {
			rnd := rand.Uint64()
			url := fmt.Sprintf("http://localhost:%d?rand=%d", port, rnd)

			_, err := httpcl.Get(url)
			require.Error(t, err)
		})
	}

	for i, port := range []int{10200, 10201} {
		t.Run(fmt.Sprintf("proxy-proto-%d:%d", i, port), func(t *testing.T) {
			conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
			require.NoError(t, err)
			defer conn.Close()

			_, err = conn.Write([]byte("abc\n"))
			require.NoError(t, err)

			buf := bufio.NewReader(conn)
			hdr, err := proxyproto.Read(buf)
			require.NoError(t, err)
			require.NotNil(t, hdr)
			require.Equal(t, byte(i+1), hdr.Version)
			require.Equal(t, conn.LocalAddr(), hdr.SourceAddr)
			require.Equal(t, conn.RemoteAddr(), hdr.DestinationAddr)

			rest, err := buf.ReadBytes('\n')
			require.NoError(t, err)
			require.Equal(t, "abc\n", string(rest))
		})
	}

	fmt.Println("stopping all")
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
