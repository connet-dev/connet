package logc

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/connet-dev/connet/reliable"
	"github.com/klev-dev/klevdb"
	"github.com/klev-dev/klevdb/compact"
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

	Get(k K) (V, error)
	GetOrDefault(k K, v V) (V, error)
	GetOrInit(k K, fn func(K) (V, error)) (V, error)

	Consume(ctx context.Context, offset int64) ([]Message[K, V], int64, error)
	Snapshot() ([]Message[K, V], int64, error) // TODO this could possible return too much data

	Compact(ctx context.Context) error
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
		return nil, fmt.Errorf("log open: %w", err)
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

func (l *kv[K, V]) Get(k K) (V, error) {
	msg, err := l.log.GetByKey(k, false)
	if err != nil {
		var v V
		return v, err
	}
	if msg.ValueEmpty {
		var v V
		return v, fmt.Errorf("key not found: %w", ErrNotFound)
	}
	return msg.Value, nil
}

func (l *kv[K, V]) GetOrDefault(k K, dv V) (V, error) {
	switch v, err := l.Get(k); {
	case err == nil:
		return v, nil
	case errors.Is(err, ErrNotFound):
		return dv, nil
	default:
		return v, err
	}
}

func (l *kv[K, V]) GetOrInit(k K, fn func(K) (V, error)) (V, error) {
	switch v, err := l.Get(k); {
	case err == nil:
		return v, nil
	case errors.Is(err, ErrNotFound):
		nv, err := fn(k)
		if err != nil {
			return v, err
		}
		if err := l.Put(k, nv); err != nil {
			return v, err
		}
		return nv, nil
	default:
		return v, err
	}
}

func (l *kv[K, V]) Consume(ctx context.Context, offset int64) ([]Message[K, V], int64, error) {
	nextOffset, msgs, err := l.log.ConsumeBlocking(ctx, offset, 32)
	if err != nil {
		return nil, OffsetInvalid, err
	}
	nmsgs := make([]Message[K, V], len(msgs))
	for i, msg := range msgs {
		nmsgs[i] = Message[K, V]{
			Offset: msg.Offset,
			Key:    msg.Key,
			Value:  msg.Value,
			Delete: msg.ValueEmpty,
		}
	}
	return nmsgs, nextOffset, nil
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

func (l *kv[K, V]) Compact(ctx context.Context) error {
	updatesBefore := time.Now().Add(-6 * time.Hour)
	if _, _, err := compact.UpdatesMulti(ctx, l.log.Raw(), updatesBefore, compactBackoff); err != nil {
		return err
	}
	deletesBefore := time.Now().Add(-12 * time.Hour)
	if _, _, err := compact.DeletesMulti(ctx, l.log.Raw(), deletesBefore, compactBackoff); err != nil {
		return err
	}
	return l.log.GC(0)
}

func (l *kv[K, V]) Close() error {
	return l.log.Close()
}

func compactBackoff(ctx context.Context) error {
	return reliable.WaitDeline(ctx, time.Second)
}

func ScheduleCompact[K comparable, V any](l KV[K, V]) reliable.RunFn {
	return reliable.ScheduleDelayed(5*time.Minute, time.Hour, l.Compact)
}

func ScheduleCompactAcc[K comparable, V any](l KV[K, V]) reliable.RunFn {
	return reliable.ScheduleDelayed(1*time.Minute, time.Hour, l.Compact)
}
