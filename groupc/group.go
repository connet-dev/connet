package groupc

import (
	"context"

	"golang.org/x/sync/errgroup"
)

type Run func(context.Context) error

type G struct {
	group *errgroup.Group
	ctx   context.Context
}

func New(ctx context.Context) *G {
	group, ctx := errgroup.WithContext(ctx)
	return &G{
		group: group,
		ctx:   ctx,
	}
}

func (g *G) Go(fn Run) {
	g.group.Go(func() error {
		return fn(g.ctx)
	})
}

func (g *G) Wait() error {
	return g.group.Wait()
}
