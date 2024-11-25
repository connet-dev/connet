package notify

import (
	"context"
	"sync/atomic"

	"github.com/klev-dev/kleverr"
)

type N struct {
	value   atomic.Uint64
	barrier chan chan struct{}
}

func New() *N {
	n := &N{
		barrier: make(chan chan struct{}, 1),
	}
	n.barrier <- make(chan struct{})

	return n
}

func (n *N) Get(ctx context.Context, version uint64) (uint64, error) {
	if current := n.value.Load(); current > version {
		return current, nil
	}

	b, ok := <-n.barrier
	if !ok {
		return 0, kleverr.Newf("already closed")
	}

	current := n.value.Load()

	n.barrier <- b

	if current > version {
		return current, nil
	}

	select {
	case <-b:
		updated := n.value.Load()
		if updated <= version {
			panic("hmmmm")
		}
		return updated, nil
	case <-ctx.Done():
		return 0, kleverr.Newf("context closed: %w", ctx.Err())
	}
}

func (n *N) Listen(ctx context.Context, f func() error) error {
	var version uint64
	var err error
	for {
		version, err = n.Get(ctx, version)
		if err != nil {
			return err
		}
		if err := f(); err != nil {
			return err
		}
	}
}

func (n *N) Updated() {
	b, ok := <-n.barrier
	if !ok {
		return
	}

	n.value.Add(1)

	close(b)

	n.barrier <- make(chan struct{})
}

func (n *N) Close() {
	b, ok := <-n.barrier
	if !ok {
		return
	}

	close(b)

	close(n.barrier)
}
