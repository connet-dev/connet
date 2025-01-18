package quicc

import (
	"time"

	"github.com/quic-go/quic-go"
)

var StdConfig = &quic.Config{
	MaxIdleTimeout:  20 * time.Second,
	KeepAlivePeriod: 10 * time.Second,
	Tracer:          RTTTracer,
}
