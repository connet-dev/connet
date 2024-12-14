package logc

import (
	"cmp"
	"context"
	"slices"
	"sync"

	"github.com/klev-dev/kleverr"
)

const (
	OffsetInvalid int64 = -3
	OffsetOldest  int64 = -2
	OffsetNewest  int64 = -1
)

type Message[K any, V any] struct {
	Offset int64
	Key    K
	Value  V
	Delete bool
}

type Log[K any, V any] interface {
	Consume(ctx context.Context, offset int64) ([]Message[K, V], int64, error)
	NextOffset() (int64, error)

	Put(k K, v V) (int64, error)
	PutDel(k K, v V) (int64, error)
	Del(k K) (int64, error)
}

func NewMemoryLog[K any, V any]() Log[K, V] {
	return &memLog[K, V]{
		notify: newOffsetNotify(0),
	}
}

type memLog[K any, V any] struct {
	nextOffset int64
	msgs       []Message[K, V]
	mu         sync.RWMutex
	notify     *offsetNotify
}

func (m *memLog[K, V]) Consume(ctx context.Context, offset int64) ([]Message[K, V], int64, error) {
	if err := m.notify.Wait(ctx, offset); err != nil {
		return nil, OffsetInvalid, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	switch {
	case offset <= OffsetInvalid:
		return nil, OffsetInvalid, kleverr.Newf("invalid offset: %d it negative", offset)
	case offset > m.nextOffset:
		return nil, OffsetInvalid, kleverr.Newf("invalid offset: %d does not exist", offset)
	case offset == OffsetNewest || offset == m.nextOffset:
		return nil, m.nextOffset, nil
	case offset == OffsetOldest:
		if len(m.msgs) == 0 {
			return nil, m.nextOffset, nil
		}
		msgs := m.msgs[0:min(32, len(m.msgs))]
		return msgs, msgs[len(msgs)-1].Offset + 1, nil
	case len(m.msgs) == 0:
		return nil, m.nextOffset, nil
	case offset < m.msgs[0].Offset:
		return nil, m.msgs[0].Offset, nil
	}

	pos, _ := slices.BinarySearchFunc(m.msgs, offset, func(msg Message[K, V], offset int64) int {
		return cmp.Compare(msg.Offset, offset)
	})
	msgs := m.msgs[pos:min(pos+32, len(m.msgs))]
	return msgs, msgs[len(msgs)-1].Offset + 1, nil
}

func (m *memLog[K, V]) NextOffset() (int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.nextOffset, nil
}

func (m *memLog[K, V]) Put(k K, v V) (int64, error) {
	return m.publishNotify(Message[K, V]{
		Key:   k,
		Value: v,
	})
}

func (m *memLog[K, V]) PutDel(k K, v V) (int64, error) {
	return m.publishNotify(Message[K, V]{
		Key:    k,
		Value:  v,
		Delete: true,
	})
}

func (m *memLog[K, V]) Del(k K) (int64, error) {
	return m.publishNotify(Message[K, V]{
		Key:    k,
		Delete: true,
	})
}

func (m *memLog[K, V]) publishNotify(msg Message[K, V]) (int64, error) {
	offset, err := m.publish(msg)
	if err != nil {
		return 0, err
	}
	m.notify.Set(offset)
	return offset, nil
}

func (m *memLog[K, V]) publish(msg Message[K, V]) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	msg.Offset = m.nextOffset
	m.msgs = append(m.msgs, msg)

	m.nextOffset++
	return m.nextOffset, nil
}
