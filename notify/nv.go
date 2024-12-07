package notify

import (
	"context"
	"sync/atomic"

	"github.com/klev-dev/kleverr"
)

type NV[T any] struct {
	value   atomic.Pointer[nvalue[T]]
	barrier chan *nversion[T]
}

type nvalue[T any] struct {
	value   T
	version uint64
}

type nversion[T any] struct {
	value   T
	version uint64
	waiter  chan struct{}
}

func NewNV[T any]() *NV[T] {
	n := &NV[T]{
		barrier: make(chan *nversion[T], 1),
	}
	n.barrier <- &nversion[T]{waiter: make(chan struct{})}
	return n
}

func (n *NV[T]) Get(ctx context.Context, version uint64) (T, uint64, error) {
	if current := n.value.Load(); current != nil && current.version > version {
		return current.value, current.version, nil
	}

	next, ok := <-n.barrier
	if !ok {
		var t T
		return t, 0, kleverr.New("already closed")
	}

	current := n.value.Load()

	n.barrier <- next

	if current != nil && current.version > version {
		return current.value, current.version, nil
	}

	select {
	case <-next.waiter:
		return next.value, next.version, nil
	case <-ctx.Done():
		var t T
		return t, 0, kleverr.Newf("context closed: %w", ctx.Err())
	}
}

func (n *NV[T]) GetAny(ctx context.Context) (T, uint64, error) {
	if current := n.value.Load(); current != nil {
		return current.value, current.version, nil
	}

	next, ok := <-n.barrier
	if !ok {
		var t T
		return t, 0, kleverr.New("already closed")
	}

	current := n.value.Load()

	n.barrier <- next

	if current != nil {
		return current.value, current.version, nil
	}

	select {
	case <-next.waiter:
		return next.value, next.version, nil
	case <-ctx.Done():
		var t T
		return t, 0, kleverr.Newf("context closed: %w", ctx.Err())
	}
}

func (n *NV[T]) Set(t T) {
	n.SetFunc(func(_ T) T {
		return t
	})
}

func (n *NV[T]) Update(f func(t T)) {
	n.SetFunc(func(t T) T {
		f(t)
		return t
	})
}

func (n *NV[T]) SetFunc(f func(t T) T) {
	next, ok := <-n.barrier
	if !ok {
		return
	}

	if current := n.value.Load(); current != nil {
		next.value = f(current.value)
		next.version = current.version + 1
	} else {
		var t T
		next.value = f(t)
	}
	n.value.Store(&nvalue[T]{next.value, next.version})

	close(next.waiter)

	n.barrier <- &nversion[T]{waiter: make(chan struct{})}
}

func (n *NV[T]) Listen(ctx context.Context, f func(t T) error) error {
	t, v, err := n.GetAny(ctx)
	if err != nil {
		return err
	}
	if err := f(t); err != nil {
		return err
	}
	for {
		t, v, err = n.Get(ctx, v)
		if err != nil {
			return err
		}
		if err := f(t); err != nil {
			return err
		}
	}
}

func (n *NV[T]) Notify(ctx context.Context) <-chan T {
	ch := make(chan T, 1)
	go func() {
		defer close(ch)
		n.Listen(ctx, func(t T) error {
			ch <- t
			return nil
		})
	}()
	return ch
}
