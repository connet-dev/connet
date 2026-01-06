package nat

import (
	"context"
	"log/slog"
	"net/netip"

	"github.com/connet-dev/connet/pkg/netc"
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
	if err == nil {
		localAddrPorts := make([]netip.AddrPort, len(localAddrs))
		for i, addr := range localAddrs {
			localAddrPorts[i] = netip.AddrPortFrom(addr, s.localPort)
		}
		return localAddrPorts
	} else {
		s.logger.Warn("cannot get local addrs", "err", err)
	}

	return nil
}

func (s *Local) Listen(ctx context.Context, fn func([]netip.AddrPort) error) error {
	return nil
}
