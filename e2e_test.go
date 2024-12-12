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

	"github.com/keihaya-com/connet/certc"
	"github.com/keihaya-com/connet/model"
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

	srv, err := NewServer(
		ServerClientTokens("test-token"),
		serverControlCertificate(cert),
		ServerLogger(logger.With("test", "server")),
	)
	require.NoError(t, err)

	clDst, err := NewClient(
		ClientToken("test-token"),
		ClientControlAddress("localhost:19190"),
		clientControlCAs(cas),
		ClientDirectAddress(":19192"),
		ClientDestination("direct", hts.Listener.Addr().String(), model.RouteDirect),
		ClientDestination("relay", hts.Listener.Addr().String(), model.RouteRelay),
		ClientLogger(logger.With("test", "cl-dst")),
	)
	require.NoError(t, err)

	clSrc, err := NewClient(
		ClientToken("test-token"),
		ClientControlAddress("localhost:19190"),
		clientControlCAs(cas),
		ClientDirectAddress(":19193"),
		ClientSource("direct", ":9990", model.RouteDirect),
		ClientSource("relay", ":9991", model.RouteRelay),
		ClientLogger(logger.With("test", "cl-src")),
	)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error { return srv.Run(ctx) })
	time.Sleep(time.Millisecond) // time for server to come online

	g.Go(func() error { return clDst.Run(ctx) })
	g.Go(func() error { return clSrc.Run(ctx) })
	time.Sleep(100 * time.Millisecond) // time for clients to come online

	// actual test
	httpcl := &http.Client{}
	httpcl.Transport = &http.Transport{DisableKeepAlives: true}

	ports := slices.Repeat([]int{9990, 9991}, 10)
	for i, port := range ports {
		t.Run(fmt.Sprintf("%d:%d", i, port), func(t *testing.T) {
			rnd := rand.Uint64()
			url := fmt.Sprintf("http://localhost:%d?rand=%d", port, rnd)

			resp, err := httpcl.Get(url)
			require.NoError(t, err)

			respData, err := io.ReadAll(resp.Body)
			defer resp.Body.Close()
			require.NoError(t, err)

			require.Equal(t, fmt.Sprintf("hello:%d", rnd), string(respData))
		})
	}

	fmt.Println("stopping all")
	cancel()

	g.Wait()
}
