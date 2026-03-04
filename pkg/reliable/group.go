package reliable

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"
)

// ErrServerStopped is the cancel cause used when a server is stopped via Stop().
var ErrServerStopped = errors.New("server stopped")

// DefaultStopTimeout is the default timeout for graceful server shutdown.
const DefaultStopTimeout = 30 * time.Second

type RunFn func(context.Context) error

func Bind[T any](t T, fn func(context.Context, T) error) RunFn {
	return func(ctx context.Context) error {
		return fn(ctx, t)
	}
}

func Schedule(d time.Duration, fn RunFn) RunFn {
	return ScheduleDelayed(d, d, fn)
}

func ScheduleNow(d time.Duration, fn RunFn) RunFn {
	return func(ctx context.Context) error {
		return rerunDeline(ctx, d, fn)
	}
}

func ScheduleDelayed(delay, d time.Duration, fn RunFn) RunFn {
	return func(ctx context.Context) error {
		if err := Wait(ctx, NextDeline(delay)); err != nil {
			return err
		}

		return rerunDeline(ctx, d, fn)
	}
}

type Group struct {
	group *errgroup.Group
	ctx   context.Context
}

func NewGroup(ctx context.Context) *Group {
	group, ctx := errgroup.WithContext(ctx)
	return &Group{
		group: group,
		ctx:   ctx,
	}
}

func RunGroup(ctx context.Context, fns ...RunFn) error {
	return NewGroup(ctx).Go(fns...).Wait()
}

func (g *Group) Go(fns ...RunFn) *Group {
	for _, fn := range fns {
		g.group.Go(func() error {
			return fn(g.ctx)
		})
	}
	return g
}

func (g *Group) Wait() error {
	return g.group.Wait()
}

// NewReadyNotifier creates a readiness notification function for n concurrent listeners.
// It signals ch once all n listeners succeed (sending nil), or immediately on any failure
// (sending the error). If n is 0, ch receives nil immediately and the returned function
// is a no-op.
func NewReadyNotifier(n int, ch chan<- error) func(error) {
	if n <= 0 {
		ch <- nil
		return func(error) {}
	}
	var once sync.Once
	var remaining atomic.Int32
	remaining.Store(int32(n))
	return func(err error) {
		if err != nil {
			once.Do(func() { ch <- err })
			return
		}
		if remaining.Add(-1) == 0 {
			once.Do(func() { ch <- nil })
		}
	}
}
