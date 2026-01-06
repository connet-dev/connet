package quicc

import (
	"context"

	"github.com/quic-go/quic-go"
)

func CancelStream(stream *quic.Stream) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		<-ctx.Done()
		stream.CancelRead(0)
		return nil
	}
}
