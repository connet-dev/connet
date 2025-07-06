package reliable

import (
	"context"
	"time"

	"golang.org/x/sync/errgroup"
)

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
