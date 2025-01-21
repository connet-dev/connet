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
		ClientDestination("direct", htAddr, model.RouteDirect),
		ClientDestination("relay", htAddr, model.RouteRelay),
		ClientDestination("dst-any-direct-src", htAddr, model.RouteAny),
		ClientDestination("dst-any-relay-src", htAddr, model.RouteAny),
		ClientDestination("dst-direct-any-src", htAddr, model.RouteDirect),
		ClientDestination("dst-relay-any-src", htAddr, model.RouteRelay),
		ClientDestination("dst-direct-relay-src", htAddr, model.RouteDirect),
		ClientDestination("dst-relay-direct-src", htAddr, model.RouteRelay),
		ClientDestinationPP("dst-direct-proxy-proto", ppAddr, model.RouteDirect, model.V1),
		ClientDestinationPP("dst-relay-proxy-proto", ppAddr, model.RouteRelay, model.V2),
		ClientLogger(logger.With("test", "cl-dst")),
	)
	require.NoError(t, err)

	clSrc, err := NewClient(
		ClientToken("test-token-src"),
		ClientControlAddress("localhost:20000"),
		clientControlCAs(cas),
		ClientDirectAddress(":20003"),
		ClientSource("direct", ":9990", model.RouteDirect),
		ClientSource("relay", ":9991", model.RouteRelay),
		ClientSource("dst-any-direct-src", ":9992", model.RouteDirect),
		ClientSource("dst-any-relay-src", ":9993", model.RouteRelay),
		ClientSource("dst-direct-any-src", ":9994", model.RouteAny),
		ClientSource("dst-relay-any-src", ":9995", model.RouteAny),
		ClientSource("dst-direct-relay-src", ":9996", model.RouteRelay),
		ClientSource("dst-relay-direct-src", ":9997", model.RouteDirect),
		ClientSource("dst-direct-proxy-proto", ":9998", model.RouteAny),
		ClientSource("dst-relay-proxy-proto", ":9999", model.RouteAny),
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
			ClientDestination("direct", hts.Listener.Addr().String(), model.RouteDirect),
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
			ClientDestination("direct", hts.Listener.Addr().String(), model.RouteDirect),
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
			ClientDestination("direct", hts.Listener.Addr().String(), model.RouteDirect),
			ClientLogger(logger.With("test", "cl-role-deny")),
		)
		require.NoError(t, err)

		require.ErrorContains(t, clNameDeny.Run(ctx), "role not allowed")
	})

	g.Go(func() error { return clDst.Run(ctx) })
	g.Go(func() error { return clSrc.Run(ctx) })
	time.Sleep(300 * time.Millisecond) // time for clients to come online

	// actual test
	httpcl := &http.Client{}
	httpcl.Transport = &http.Transport{DisableKeepAlives: true}

	// Positive
	ports := slices.Repeat([]int{9990, 9991, 9992, 9993, 9994, 9995}, 3)
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

	for i, port := range []int{9996, 9997} {
		t.Run(fmt.Sprintf("failing-%d:%d", i, port), func(t *testing.T) {
			rnd := rand.Uint64()
			url := fmt.Sprintf("http://localhost:%d?rand=%d", port, rnd)

			_, err := httpcl.Get(url)
			require.Error(t, err)
		})
	}

	for i, port := range []int{9998, 9999} {
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
