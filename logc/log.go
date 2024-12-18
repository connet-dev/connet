package logc

import (
	"cmp"
	"context"
	"maps"
	"slices"

	"github.com/klev-dev/klevdb"
	"github.com/klev-dev/kleverr"
)

const (
	OffsetInvalid = klevdb.OffsetInvalid
	OffsetOldest  = klevdb.OffsetOldest
	OffsetNewest  = klevdb.OffsetNewest
)

var ErrNotFound = klevdb.ErrNotFound

type Message[K comparable, V any] struct {
	Offset int64
	Key    K
	Value  V
	Delete bool
}

type KV[K comparable, V any] interface {
	Put(k K, v V) error
	Del(k K) error

	Consume(ctx context.Context, offset int64) ([]Message[K, V], int64, error)
	Get(k K) (V, error)

	Snapshot() ([]Message[K, V], int64, error) // TODO this could possible return too much data

	Close() error
}

func NewKV[K comparable, V any](dir string) (KV[K, V], error) {
	log, err := klevdb.OpenTBlocking(dir, klevdb.Options{
		CreateDirs: true,
		KeyIndex:   true,
		AutoSync:   true,
		Check:      true,
	}, klevdb.JsonCodec[K]{}, klevdb.JsonCodec[V]{})
	if err != nil {
		return nil, err
	}
	return &kv[K, V]{log}, nil
}

type kv[K comparable, V any] struct {
	log klevdb.TBlockingLog[K, V]
}

func (l *kv[K, V]) Put(k K, v V) error {
	_, err := l.log.Publish([]klevdb.TMessage[K, V]{{
		Key:   k,
		Value: v,
	}})
	return err
}

func (l *kv[K, V]) Del(k K) error {
	_, err := l.log.Publish([]klevdb.TMessage[K, V]{{
		Key:        k,
		ValueEmpty: true,
	}})
	return err
}

func (l *kv[K, V]) Consume(ctx context.Context, offset int64) ([]Message[K, V], int64, error) {
	nextOffset, msgs, err := l.log.ConsumeBlocking(ctx, offset, 32)
	if err != nil {
		return nil, OffsetInvalid, err
	}
	var nmsgs []Message[K, V]
	for _, msg := range msgs {
		nmsgs = append(nmsgs, Message[K, V]{
			Offset: msg.Offset,
			Key:    msg.Key,
			Value:  msg.Value,
			Delete: msg.ValueEmpty,
		})
	}
	return nmsgs, nextOffset, nil
}

func (l *kv[K, V]) Get(k K) (V, error) {
	msg, err := l.log.GetByKey(k, false)
	if err != nil {
		var v V
		return v, err
	}
	if msg.ValueEmpty {
		var v V
		return v, kleverr.Newf("key not found: %w", ErrNotFound)
	}
	return msg.Value, nil
}

func (l *kv[K, V]) Snapshot() ([]Message[K, V], int64, error) {
	maxOffset, err := l.log.NextOffset()
	if err != nil {
		return nil, OffsetInvalid, err
	}

	sum := map[K]Message[K, V]{}
	for offset := OffsetOldest; offset < maxOffset; {
		nextOffset, msgs, err := l.log.Consume(offset, 32)
		if err != nil {
			return nil, OffsetInvalid, err
		}
		offset = nextOffset

		for _, msg := range msgs {
			if msg.ValueEmpty {
				delete(sum, msg.Key)
			} else {
				sum[msg.Key] = Message[K, V]{
					Offset: msg.Offset,
					Key:    msg.Key,
					Value:  msg.Value,
				}
			}
		}
	}

	return slices.SortedFunc(maps.Values(sum), func(l, r Message[K, V]) int {
		return cmp.Compare(l.Offset, r.Offset)
	}), maxOffset, nil
}

func (l *kv[K, V]) Close() error {
	return l.log.Close()
}
