package notify

import (
	"context"
	"maps"
	"sync"
)

type V[T any] struct {
	value T
	mu    sync.RWMutex
	n     *N
	cp    func(T) T
}

func NewV[T any](opts ...VOpt[T]) *V[T] {
	v := &V[T]{
		n: New(),
	}
	for _, opt := range opts {
		opt(v)
	}
	if v.cp == nil {
		v.cp = func(t T) T { return t }
	}
	return v
}

func (v *V[T]) Set(t T) {
	defer v.n.Updated()

	v.mu.Lock()
	defer v.mu.Unlock()

	v.value = t
}

func (v *V[T]) Update(f func(T)) {
	defer v.n.Updated()

	v.mu.Lock()
	defer v.mu.Unlock()

	f(v.value)
}

func (v *V[T]) Get() T {
	v.mu.RLock()
	defer v.mu.RUnlock()

	return v.cp(v.value)
}

func (v *V[T]) Read(f func(T)) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	f(v.value)
}

func (v *V[T]) Listen(ctx context.Context, f func(t T) error) error {
	return v.n.Listen(ctx, func() error {
		return f(v.Get())
	})
}

type VOpt[T any] func(*V[T])

func CopyOpt[T any](cp func(T) T) VOpt[T] {
	return func(v *V[T]) {
		v.cp = cp
	}
}

func CopyMapOpt[T map[K]R, K comparable, R any]() VOpt[T] {
	return func(v *V[T]) {
		v.cp = maps.Clone
	}
}

func InitialOpt[T any](t T) VOpt[T] {
	return func(v *V[T]) {
		v.value = t
	}
}
