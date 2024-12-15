package logc

import (
	"cmp"
	"context"
	"maps"
	"slices"
	"time"
)

type KV[K comparable, V any] interface {
	Log[K, V]

	Put(k K, v V) (int64, error)
	PutDel(k K, v V) (int64, error)
	Del(k K) (int64, error)

	Map(ctx context.Context) (map[K]V, int64, error)
	Snapshot(ctx context.Context) ([]Message[K, V], int64, error)

	Listen(ctx context.Context, f func(map[K]V) error) error

	Compact(ctx context.Context, age time.Duration) error
}

func NewMemoryKVLog[K comparable, V any]() KV[K, V] {
	return &kv[K, V]{
		Log: NewMemoryLog[K, V](),
	}
}

type kv[K comparable, V any] struct {
	Log[K, V]
}

func (m *kv[K, V]) Put(k K, v V) (int64, error) {
	return m.Publish(Message[K, V]{
		Key:   k,
		Value: v,
	})
}

func (m *kv[K, V]) PutDel(k K, v V) (int64, error) {
	return m.Publish(Message[K, V]{
		Key:    k,
		Value:  v,
		Delete: true,
	})
}

func (m *kv[K, V]) Del(k K) (int64, error) {
	return m.Publish(Message[K, V]{
		Key:    k,
		Delete: true,
	})
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

func (m *kv[K, V]) Compact(ctx context.Context, age time.Duration) error {
	cutoff := time.Now().Add(-age)

	maxOffset, err := m.NextOffset()
	if err != nil {
		return err
	}

	lastSet := map[K]Message[K, V]{}
	deleteSet := map[int64]struct{}{}

CUTOFF:
	for offset := OffsetOldest; offset < maxOffset; {
		msgs, nextOffset, err := m.Consume(ctx, offset)
		if err != nil {
			return err
		}
		offset = nextOffset

		for _, msg := range msgs {
			if msg.Time.After(cutoff) {
				break CUTOFF
			}

			if oldMsg, ok := lastSet[msg.Key]; ok {
				// if we've seen this key before, mark it for deletion
				deleteSet[oldMsg.Offset] = struct{}{}
			}

			if msg.Delete {
				deleteSet[msg.Offset] = struct{}{}
			} else {
				lastSet[msg.Key] = msg
			}
		}
	}

	return m.Delete(deleteSet)
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
