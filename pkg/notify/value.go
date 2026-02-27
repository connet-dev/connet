package notify

import (
	"context"
	"errors"
	"maps"
	"slices"
	"sync/atomic"

	"github.com/connet-dev/connet/pkg/iterc"
)

var errNotifyClosed = errors.New("notify already closed")

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
		return t, 0, errNotifyClosed
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
		return t, 0, ctx.Err()
	}
}

func (v *V[T]) GetAny(ctx context.Context) (T, uint64, error) {
	if current := v.value.Load(); current != nil {
		return current.value, current.version, nil
	}

	next, ok := <-v.barrier
	if !ok {
		var t T
		return t, 0, errNotifyClosed
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
		return t, 0, ctx.Err()
	}
}

func (v *V[T]) Peek() (T, bool) {
	if current := v.value.Load(); current != nil {
		return current.value, true
	}
	return *new(T), false
}

func (v *V[T]) Sync(f func()) {
	next, ok := <-v.barrier
	if !ok {
		return
	}
	defer func() {
		v.barrier <- next
	}()

	f()
}

func (v *V[T]) Set(t T) {
	v.UpdateOpt(func(_ T) (T, bool) {
		return t, true
	})
}

func (v *V[T]) Update(f func(t T) T) {
	v.UpdateOpt(func(t T) (T, bool) {
		return f(t), true
	})
}

func (v *V[T]) UpdateOpt(f func(t T) (T, bool)) bool {
	next, ok := <-v.barrier
	if !ok {
		return false
	}

	if current := v.value.Load(); current != nil {
		if value, updated := f(current.value); updated {
			next.value = value
			next.version = current.version + 1
		} else {
			v.barrier <- next
			return false
		}
	} else {
		var t T
		if value, updated := f(t); updated {
			next.value = value
			next.version = 0
		} else {
			v.barrier <- next
			return false
		}
	}
	v.value.Store(&value[T]{next.value, next.version})

	close(next.waiter)

	v.barrier <- &version[T]{waiter: make(chan struct{})}

	return true
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
		_ = v.Listen(ctx, func(t T) error {
			ch <- t
			return nil
		})
	}()
	return ch
}

func SliceAppend[S []T, T any](v *V[S], val T) {
	v.Update(func(t S) S {
		return append(slices.Clone(t), val)
	})
}

func SliceRemove[S []T, T comparable](v *V[S], val T) {
	v.Update(func(t S) S {
		return iterc.FilterSlice(t, func(el T) bool { return el != val })
	})
}

func SliceFilter[S []T, T any](v *V[S], fn func(t T) bool) {
	v.Update(func(t S) S {
		return iterc.FilterSlice(t, fn)
	})
}

func MapPut[M ~map[K]T, K comparable, T any](m *V[M], k K, v T) {
	m.Update(func(t M) M {
		if t == nil {
			t = map[K]T{}
		} else {
			t = maps.Clone(t)
		}
		t[k] = v
		return t
	})
}

func MapDelete[M ~map[K]T, K comparable, T any](m *V[M], k K) {
	m.Update(func(t M) M {
		t = maps.Clone(t)
		delete(t, k)
		return t
	})
}

func MapDeleteFunc[M ~map[K]T, K comparable, T any](m *V[M], del func(K, T) bool) {
	m.Update(func(t M) M {
		t = maps.Clone(t)
		maps.DeleteFunc(t, del)
		return t
	})
}

func ListenMulti[L any, R any](ctx context.Context, nl *V[L], nr *V[R], fn func(context.Context, L, R) error) error {
	var l L
	var r R
	var ok bool

	cl := nl.Notify(ctx)
	cr := nr.Notify(ctx)

	for {
		select {
		case l, ok = <-cl:
			if !ok {
				return errNotifyClosed
			}
			if err := fn(ctx, l, r); err != nil {
				return err
			}
		case r, ok = <-cr:
			if !ok {
				return errNotifyClosed
			}
			if err := fn(ctx, l, r); err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
