package logc

import (
	"context"
	"errors"
	"sync/atomic"

	"github.com/klev-dev/kleverr"
)

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
