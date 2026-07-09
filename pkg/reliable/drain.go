package reliable

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type Drain struct {
	ctx context.Context
	wg  sync.WaitGroup
}

func NewDrain(ctx context.Context) *Drain {
	return &Drain{ctx: ctx}
}

func (d *Drain) Go(f func(context.Context)) {
	d.wg.Go(func() { f(d.ctx) })
}

func (d *Drain) Wait(timeout time.Duration) error {
	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()

	drainCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	select {
	case <-done:
		return nil
	case <-drainCtx.Done():
		return fmt.Errorf("drain timeout")
	}
}
