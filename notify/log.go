package notify

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/klev-dev/kleverr"
)

const (
	MessageInvalid int64 = -3
	MessageOldest  int64 = -2
	MessageNewest  int64 = -1
)

type Message[K any, V any] struct {
	Offset int64
	Key    K
	Value  V
	Delete bool
}

type Log[K any, V any] interface {
	Consume(ctx context.Context, offset int64) ([]Message[K, V], int64, error)

	Put(k K, v V) (int64, error)
	Del(k K, v V) (int64, error)
}

func NewMemoryLog[K any, V any]() Log[K, V] {
	return &memMessages[K, V]{
		notify: newOffsetNotify(0),
	}
}

type memMessages[K any, VV any] struct {
	nextOffset int64
	msgs       []Message[K, VV]
	mu         sync.RWMutex
	notify     *offsetNotify
}

func (m *memMessages[K, V]) Consume(ctx context.Context, offset int64) ([]Message[K, V], int64, error) {
	if err := m.notify.Wait(ctx, offset); err != nil {
		return nil, MessageInvalid, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	switch {
	case offset <= MessageInvalid:
		return nil, MessageInvalid, kleverr.Newf("invalid offset: %d it negative", offset)
	case offset > m.nextOffset:
		return nil, MessageInvalid, kleverr.Newf("invalid offset: %d does not exist", offset)
	case offset == MessageNewest || offset == m.nextOffset:
		return nil, m.nextOffset, nil
	case offset == MessageOldest:
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

func (m *memMessages[K, V]) Put(k K, v V) (int64, error) {
	return m.publishNotify(Message[K, V]{
		Key:   k,
		Value: v,
	})
}

func (m *memMessages[K, V]) Del(k K, v V) (int64, error) {
	return m.publishNotify(Message[K, V]{
		Key:    k,
		Value:  v,
		Delete: true,
	})
}

func (m *memMessages[K, V]) publishNotify(msg Message[K, V]) (int64, error) {
	offset, err := m.publish(msg)
	if err != nil {
		return 0, err
	}
	m.notify.Set(offset)
	return offset, nil
}

func (m *memMessages[K, V]) publish(msg Message[K, V]) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	msg.Offset = m.nextOffset
	m.msgs = append(m.msgs, msg)

	m.nextOffset++
	return m.nextOffset, nil
}

var errOffsetNotifyClosed = errors.New("offset notify already closed")

type offsetNotify struct {
	nextOffset atomic.Int64
	barrier    chan chan struct{}
}

func newOffsetNotify(nextOffset int64) *offsetNotify {
	w := &offsetNotify{
		barrier: make(chan chan struct{}, 1),
	}

	w.nextOffset.Store(nextOffset)
	w.barrier <- make(chan struct{})

	return w
}

func (w *offsetNotify) Wait(ctx context.Context, offset int64) error {
	// quick path, just load and check
	if w.nextOffset.Load() > offset {
		return nil
	}

	// acquire current barrier
	b, ok := <-w.barrier
	if !ok {
		// already closed, return error
		return kleverr.Ret(errOffsetNotifyClosed)
	}

	// probe the current offset
	updated := w.nextOffset.Load() > offset

	// release current barrier
	w.barrier <- b

	// already has a new value, return
	if updated {
		return nil
	}

	// now wait for something to happen
	select {
	case <-b:
		return nil
	case <-ctx.Done():
		return kleverr.Ret(ctx.Err())
	}
}

func (w *offsetNotify) Set(nextOffset int64) {
	// acquire current barrier
	b, ok := <-w.barrier
	if !ok {
		// already closed
		return
	}

	// set the new offset
	if w.nextOffset.Load() < nextOffset {
		w.nextOffset.Store(nextOffset)
	}

	// close the current barrier, e.g. broadcasting update
	close(b)

	// create new barrier
	w.barrier <- make(chan struct{})
}

func (w *offsetNotify) Close() error {
	// acquire current barrier
	b, ok := <-w.barrier
	if !ok {
		// already closed, return an error
		return kleverr.Ret(errOffsetNotifyClosed)
	}

	// close the current barrier, e.g. broadcasting update
	close(b)

	// close the barrier channel, completing process
	close(w.barrier)

	return nil
}
