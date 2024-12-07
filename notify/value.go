package notify

import (
	"context"
	"sync/atomic"

	"github.com/klev-dev/kleverr"
)

type V[T any] struct {
	value   atomic.Pointer[value[T]]
	barrier chan *version[T]
}

type value[T any] struct {
	value   T
	version uint64
}

type version[T any] struct {
	value   T
	version uint64
	waiter  chan struct{}
}

func NewEmpty[T any]() *V[T] {
	v := &V[T]{
		barrier: make(chan *version[T], 1),
	}
	v.barrier <- &version[T]{waiter: make(chan struct{})}
	return v
}

func New[T any](t T) *V[T] {
	v := &V[T]{
		barrier: make(chan *version[T], 1),
	}
	v.barrier <- &version[T]{waiter: make(chan struct{})}
	v.value.Store(&value[T]{t, 0})
	return v
}

func (v *V[T]) Get(ctx context.Context, version uint64) (T, uint64, error) {
	if current := v.value.Load(); current != nil && current.version > version {
		return current.value, current.version, nil
	}

	next, ok := <-v.barrier
	if !ok {
		var t T
		return t, 0, kleverr.New("already closed")
	}

	current := v.value.Load()

	v.barrier <- next

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

func (v *V[T]) GetAny(ctx context.Context) (T, uint64, error) {
	if current := v.value.Load(); current != nil {
		return current.value, current.version, nil
	}

	next, ok := <-v.barrier
	if !ok {
		var t T
		return t, 0, kleverr.New("already closed")
	}

	current := v.value.Load()

	v.barrier <- next

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

func (v *V[T]) Set(t T) {
	v.Update(func(_ T) T {
		return t
	})
}

func (v *V[T]) Update(f func(t T) T) {
	next, ok := <-v.barrier
	if !ok {
		return
	}

	if current := v.value.Load(); current != nil {
		next.value = f(current.value)
		next.version = current.version + 1
	} else {
		var t T
		next.value = f(t)
	}
	v.value.Store(&value[T]{next.value, next.version})

	close(next.waiter)

	v.barrier <- &version[T]{waiter: make(chan struct{})}
}

func (v *V[T]) Listen(ctx context.Context, f func(t T) error) error {
	t, ver, err := v.GetAny(ctx)
	if err != nil {
		return err
	}
	if err := f(t); err != nil {
		return err
	}
	for {
		t, ver, err = v.Get(ctx, ver)
		if err != nil {
			return err
		}
		if err := f(t); err != nil {
			return err
		}
	}
}

func (v *V[T]) Notify(ctx context.Context) <-chan T {
	ch := make(chan T, 1)
	go func() {
		defer close(ch)
		v.Listen(ctx, func(t T) error {
			ch <- t
			return nil
		})
	}()
	return ch
}

func (v *V[T]) Copying(f func(T) T) *C[T] {
	return &C[T]{v, f}
}

type C[T any] struct {
	*V[T]
	copier func(T) T
}

func (c *C[T]) Update(f func(t T)) {
	c.V.Update(func(t T) T {
		t = c.copier(t)
		f(t)
		return t
	})
}
