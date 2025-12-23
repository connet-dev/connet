package quicc

import (
	"context"

	"github.com/quic-go/quic-go"
)

func WaitStream(stream *quic.Stream) func(context.Context) error {
	return func(ctx context.Context) error {
		<-ctx.Done()
		stream.CancelRead(0)
		return nil
	}
}
