package nat

import (
	"context"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"github.com/connet-dev/connet/pkg/netc"
	"github.com/connet-dev/connet/pkg/reliable"
)

type Local struct {
	localPort uint16
	logger    *slog.Logger
}

func NewLocal(localPort uint16, logger *slog.Logger) *Local {
	return &Local{localPort, logger.With("component", "local")}
}

func (s *Local) Get() []netip.AddrPort {
	localAddrs, err := netc.LocalAddrs()
	if err != nil {
		s.logger.Warn("cannot get local addrs", "err", err)
		return nil
	}

	localAddrPorts := make([]netip.AddrPort, len(localAddrs))
	for i, addr := range localAddrs {
		localAddrPorts[i] = netip.AddrPortFrom(addr, s.localPort)
	}
	return localAddrPorts

}

func (s *Local) Listen(ctx context.Context, fn func([]netip.AddrPort) error) error {
	locals := s.Get()
	if err := fn(locals); err != nil {
		return err
	}

	for {
		if err := reliable.WaitDeline(ctx, 30*time.Second); err != nil {
			return err
		}

		newLocals := s.Get()
		if slices.Equal(locals, newLocals) {
			continue
		}

		locals = newLocals
		if err := fn(locals); err != nil {
			return err
		}
	}
}
