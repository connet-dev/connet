package quicc

import (
	"context"
	"log/slog"
	"time"

	"github.com/quic-go/quic-go"
)

func WaitLogRTTStats(ctx context.Context, conn *quic.Conn, logger *slog.Logger) error {
	LogRTTStats(conn, logger)
	for {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-conn.Context().Done():
			return context.Cause(conn.Context())
		case <-time.After(30 * time.Second):
			LogRTTStats(conn, logger)
		}
	}
}

func LogRTTStats(conn *quic.Conn, logger *slog.Logger) {
	stats := conn.ConnectionStats()
	logger.Debug("rtt stats", "last", stats.LatestRTT, "smoothed", stats.SmoothedRTT)
}
