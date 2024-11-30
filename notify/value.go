package notify

import (
	"context"
	"sync"
)

type V[T any] struct {
	value T
	mu    sync.RWMutex
	n     *N
	cp    func(T) T
}

func NewV[T any](cp func(T) T) *V[T] {
	if cp == nil {
		cp = func(t T) T { return t }
	}
	return &V[T]{
		n:  New(),
		cp: cp,
	}
}

func (v *V[T]) Set(t T) {
	defer v.n.Updated()

	v.mu.Lock()
	defer v.mu.Unlock()

	v.value = t
}

func (v *V[T]) Update(f func(T) T) {
	defer v.n.Updated()

	v.mu.Lock()
	defer v.mu.Unlock()

	v.value = f(v.value)
}

func (v *V[T]) Modify(f func(T)) {
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

func (v *V[T]) Listen(ctx context.Context, f func(t T) error) error {
	return v.n.Listen(ctx, func() error {
		return f(v.Get())
	})
}
