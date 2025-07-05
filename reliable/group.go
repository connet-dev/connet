package reliable

import (
	"context"
	"time"

	"golang.org/x/sync/errgroup"
)

type RunFn func(context.Context) error

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

func (g *Group) Go(fn RunFn) *Group {
	g.group.Go(func() error {
		return fn(g.ctx)
	})
	return g
}

func GroupGo1[T any](g *Group, t T, fn func(context.Context, T) error) {
	g.group.Go(func() error {
		return fn(g.ctx, t)
	})
}

func (g *Group) Scheduled(d time.Duration, fn RunFn) *Group {
	return g.ScheduledDelayed(d, d, fn)
}

func (g *Group) ScheduledImmediate(d time.Duration, fn RunFn) *Group {
	g.group.Go(func() error {
		return rerunDeline(g.ctx, d, fn)
	})
	return g
}

func (g *Group) ScheduledDelayed(delay, d time.Duration, fn RunFn) *Group {
	g.group.Go(func() error {
		if err := Wait(g.ctx, NextDeline(delay)); err != nil {
			return err
		}

		return rerunDeline(g.ctx, d, fn)
	})
	return g
}

func (g *Group) Wait() error {
	return g.group.Wait()
}
