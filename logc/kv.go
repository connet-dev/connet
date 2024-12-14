package logc

import (
	"cmp"
	"context"
	"maps"
	"slices"
)

type KV[K comparable, V any] interface {
	Log[K, V]

	Map(ctx context.Context) (map[K]V, int64, error)
	Snapshot(ctx context.Context) ([]Message[K, V], int64, error)

	Listen(ctx context.Context, f func(map[K]V) error) error
}

func NewMemoryKVLog[K comparable, V any]() KV[K, V] {
	return &kv[K, V]{
		Log: NewMemoryLog[K, V](),
	}
}

type kv[K comparable, V any] struct {
	Log[K, V]
}

func (m *kv[K, V]) Map(ctx context.Context) (map[K]V, int64, error) {
	return Map(ctx, m.Log)
}

func (m *kv[K, V]) Snapshot(ctx context.Context) ([]Message[K, V], int64, error) {
	return Snapshot(ctx, m.Log)
}

func (m *kv[K, V]) Listen(ctx context.Context, f func(map[K]V) error) error {
	return ListenMap(ctx, m.Log, f)
}

func Map[K comparable, V any](ctx context.Context, log Log[K, V]) (map[K]V, int64, error) {
	maxOffset, err := log.NextOffset()
	if err != nil {
		return nil, OffsetInvalid, err
	}

	sum := map[K]V{}
	for offset := OffsetOldest; offset < maxOffset; {
		msgs, nextOffset, err := log.Consume(ctx, offset)
		if err != nil {
			return nil, OffsetInvalid, err
		}
		offset = nextOffset

		for _, msg := range msgs {
			if msg.Delete {
				delete(sum, msg.Key)
			} else {
				sum[msg.Key] = msg.Value
			}
		}
	}

	return sum, maxOffset, nil
}

func Snapshot[K comparable, V any](ctx context.Context, log Log[K, V]) ([]Message[K, V], int64, error) {
	maxOffset, err := log.NextOffset()
	if err != nil {
		return nil, OffsetInvalid, err
	}

	sum := map[K]Message[K, V]{}
	for offset := OffsetOldest; offset < maxOffset; {
		msgs, nextOffset, err := log.Consume(ctx, offset)
		if err != nil {
			return nil, OffsetInvalid, err
		}
		offset = nextOffset

		for _, msg := range msgs {
			if msg.Delete {
				delete(sum, msg.Key)
			} else {
				sum[msg.Key] = msg
			}
		}
	}

	return slices.SortedFunc(maps.Values(sum), func(l, r Message[K, V]) int {
		return cmp.Compare(l.Offset, r.Offset)
	}), maxOffset, nil
}

func ListenMap[K comparable, V any](ctx context.Context, log Log[K, V], f func(map[K]V) error) error {
	data, offset, err := Map(ctx, log)
	if err != nil {
		return err
	}
	if err := f(data); err != nil {
		return err
	}

	for {
		msgs, nextOffset, err := log.Consume(ctx, offset)
		if err != nil {
			return err
		}

		for _, msg := range msgs {
			if msg.Delete {
				delete(data, msg.Key)
			} else {
				data[msg.Key] = msg.Value
			}
		}

		if err := f(data); err != nil {
			return err
		}

		offset = nextOffset
	}
}
