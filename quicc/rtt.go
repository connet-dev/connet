package quicc

import (
	"context"
	"sync/atomic"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/logging"
)

type rttContextKeyType struct{}

var rttContextKey rttContextKeyType

type rttStats struct {
	stats atomic.Pointer[logging.RTTStats]
}

func RTTContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, rttContextKey, &rttStats{})
}

func RTTTracer(ctx context.Context, pers logging.Perspective, ci quic.ConnectionID) *logging.ConnectionTracer {
	v, ok := ctx.Value(rttContextKey).(*rttStats)
	if !ok {
		return nil
	}
	return &logging.ConnectionTracer{
		UpdatedMetrics: func(rttStats *logging.RTTStats, cwnd, bytesInFlight logging.ByteCount, packetsInFlight int) {
			// make a copy of the stats at this point of time
			stats := *rttStats
			v.stats.Store(&stats)
		},
	}
}

func RTTStats(conn quic.Connection) *logging.RTTStats {
	v, ok := conn.Context().Value(rttContextKey).(*rttStats)
	if !ok {
		return nil
	}
	return v.stats.Load()
}
