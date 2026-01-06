package reliable

import (
	"context"
	"math/rand/v2"
	"sync"
	"time"
)

const (
	MinBackoff time.Duration = 10 * time.Millisecond
	MaxBackoff time.Duration = 15 * time.Second
)

func NextBackoff(d time.Duration) time.Duration {
	return NextBackoffCustom(d, MinBackoff, MaxBackoff)
}

func NextBackoffCustom(d, jmin, jmax time.Duration) time.Duration {
	dt := int64(d*3 - jmin)
	nd := jmin + time.Duration(rand.Int64N(dt))
	return min(jmax, nd)
}

type SpinBackoff struct {
	MinBackoff time.Duration
	MaxBackoff time.Duration

	init     sync.Once
	lastWait time.Time
	lastBoff time.Duration
}

// Wait will block on backoff if called too often
func (s *SpinBackoff) Wait(ctx context.Context) error {
	s.init.Do(func() {
		if s.MinBackoff == 0 {
			s.MinBackoff = MinBackoff
		}
		if s.MaxBackoff == 0 {
			s.MaxBackoff = MaxBackoff
		}
		s.MaxBackoff = max(s.MinBackoff, s.MaxBackoff)
	})

	delta := time.Since(s.lastWait)
	s.lastWait = time.Now()

	if delta > s.MaxBackoff {
		s.lastBoff = s.MinBackoff
		return nil
	}

	s.lastBoff = NextBackoffCustom(s.lastBoff, s.MinBackoff, s.MaxBackoff)
	return Wait(ctx, s.lastBoff)
}
