package quicc

import (
	"log/slog"

	"github.com/quic-go/quic-go"
)

func LogRTTStats(conn *quic.Conn, logger *slog.Logger) {
	stats := conn.ConnectionStats()
	logger.Debug("rtt stats", "last", stats.LatestRTT, "smoothed", stats.SmoothedRTT)
}
