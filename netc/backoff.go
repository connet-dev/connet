package netc

import (
	"math/rand/v2"
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
