package reliable

import (
	"context"
	"errors"
	"sync"
)

// ServerLifecycle encapsulates the Start/Done/Stop pattern shared by all servers.
// Embed this struct and delegate Start() to ServerLifecycle.Start(s.run).
// Done() and Stop() are promoted automatically via embedding.
type ServerLifecycle struct {
	once    sync.Once
	cancel  context.CancelCauseFunc
	done    chan struct{}
	stopErr error
}

// Start runs the server by calling run in a goroutine. It blocks until run signals
// readiness via the ready channel, then returns. Subsequent calls are no-ops (returns nil).
func (l *ServerLifecycle) Start(run func(context.Context, chan<- error) error) error {
	var startErr error
	l.once.Do(func() {
		ctx, cancel := context.WithCancelCause(context.Background())
		l.cancel = cancel
		l.done = make(chan struct{})

		ready := make(chan error, 1)
		go func() {
			defer close(l.done)
			l.stopErr = run(ctx, ready)
		}()
		startErr = <-ready
	})
	return startErr
}

// Done returns a channel that is closed when the server has fully stopped.
// Must be called after Start(); before Start() is called, Done() returns nil,
// and selecting on a nil channel blocks forever.
func (l *ServerLifecycle) Done() <-chan struct{} {
	return l.done
}

// Stop cancels the server context and waits for it to stop, or until ctx is done.
func (l *ServerLifecycle) Stop(ctx context.Context) error {
	if l.cancel == nil {
		return nil
	}
	l.cancel(ErrServerStopped)
	select {
	case <-l.done:
		if l.stopErr != nil &&
			!errors.Is(l.stopErr, context.Canceled) &&
			!errors.Is(l.stopErr, ErrServerStopped) {
			return l.stopErr
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
