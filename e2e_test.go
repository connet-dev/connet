package connet

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/connet-dev/connet/certc"
	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/restr"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func TestE2E(t *testing.T) {
	cert, cas, err := certc.SelfSigned("localhost")
	require.NoError(t, err)

	hts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello:%s", r.URL.Query().Get("rand"))
	}))
	defer hts.Close()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	localRestr, err := restr.ParseIP([]string{"192.0.2.0/24"}, nil)
	require.NoError(t, err)
	tetRestr, err := restr.ParseName("^tet$")
	require.NoError(t, err)

	srv, err := NewServer(
		ServerClientTokensRestricted(
			[]string{"test-token-dst", "test-token-src", "test-token-deny-ip", "test-token-deny-name"},
			[]restr.IP{{}, {}, localRestr, {}},
			[]restr.Name{{}, {}, {}, tetRestr},
		),
		serverControlCertificate(cert),
		ServerControlAddress(":20000"),
		ServerRelayAddress(":20001"),
		ServerLogger(logger.With("test", "server")),
	)
	require.NoError(t, err)

	clDst, err := NewClient(
		ClientToken("test-token-dst"),
		ClientControlAddress("localhost:20000"),
		clientControlCAs(cas),
		ClientDirectAddress(":20002"),
		ClientDestination("direct", hts.Listener.Addr().String(), model.RouteDirect),
		ClientDestination("relay", hts.Listener.Addr().String(), model.RouteRelay),
		ClientDestination("dst-any-direct-src", hts.Listener.Addr().String(), model.RouteAny),
		ClientDestination("dst-any-relay-src", hts.Listener.Addr().String(), model.RouteAny),
		ClientDestination("dst-direct-any-src", hts.Listener.Addr().String(), model.RouteDirect),
		ClientDestination("dst-relay-any-src", hts.Listener.Addr().String(), model.RouteRelay),
		ClientDestination("dst-direct-relay-src", hts.Listener.Addr().String(), model.RouteDirect),
		ClientDestination("dst-relay-direct-src", hts.Listener.Addr().String(), model.RouteRelay),
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
		ClientLogger(logger.With("test", "cl-src")),
	)
	require.NoError(t, err)

	clIPDeny, err := NewClient(
		ClientToken("test-token-deny-ip"),
		ClientControlAddress("localhost:20000"),
		clientControlCAs(cas),
		ClientDirectAddress(":20003"),
		ClientDestination("direct", hts.Listener.Addr().String(), model.RouteDirect),
		ClientLogger(logger.With("test", "cl-ip-deny")),
	)
	require.NoError(t, err)

	// clNameDeny, err := NewClient(
	// 	ClientToken("test-token-deny-name"),
	// 	ClientControlAddress("localhost:20000"),
	// 	clientControlCAs(cas),
	// 	ClientDirectAddress(":20004"),
	// 	ClientDestination("direct", hts.Listener.Addr().String(), model.RouteDirect),
	// 	ClientLogger(logger.With("test", "cl-name-deny")),
	// )
	// require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error { return srv.Run(ctx) })
	time.Sleep(time.Millisecond) // time for server to come online

	require.Error(t, clIPDeny.Run(ctx)) // TODO rich errors
	// require.Error(t, clNameDeny.Run(ctx)) // TODO rich errors

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

	fmt.Println("stopping all")
	cancel()

	// make sure everything shuts down on context cancel
	_ = g.Wait()
}
