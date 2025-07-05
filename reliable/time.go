package reliable

import (
	"context"
	"math/rand/v2"
	"time"
)

func NextDeline(d time.Duration) time.Duration {
	idur := int64(d) / 4
	change := rand.Int64N(idur * 2)
	return time.Duration(3*idur + change)
}

func Wait(ctx context.Context, d time.Duration) error {
	select {
	case <-time.After(d):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func RunDeline(ctx context.Context, d time.Duration, fn func(ctx context.Context) error) error {
	for {
		if err := fn(ctx); err != nil {
			return err
		}

		if err := Wait(ctx, NextDeline(d)); err != nil {
			return err
		}
	}
}
