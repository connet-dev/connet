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

func (g *Group) Go(fn RunFn) {
	g.group.Go(func() error {
		return fn(g.ctx)
	})
}

func GroupGo1[T any](g *Group, t T, fn func(context.Context, T) error) {
	g.group.Go(func() error {
		return fn(g.ctx, t)
	})
}

func (g *Group) GoScheduled(d time.Duration, fn RunFn) {
	g.GoScheduledDelayed(d, d, fn)
}

func (g *Group) GoScheduledImmediate(d time.Duration, fn RunFn) {
	g.group.Go(func() error {
		return RunDeline(g.ctx, d, fn)
	})
}

func (g *Group) GoScheduledDelayed(delay, d time.Duration, fn RunFn) {
	g.group.Go(func() error {
		if err := Wait(g.ctx, NextDeline(delay)); err != nil {
			return err
		}

		return RunDeline(g.ctx, d, fn)
	})
}

func (g *Group) Wait() error {
	return g.group.Wait()
}
