package nat

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/connet-dev/connet/netc"
	"github.com/connet-dev/connet/notify"
	"github.com/connet-dev/connet/slogc"
	"github.com/jackpal/gateway"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

const pmpBroadcastAddr = "224.0.0.1:5350"
const pmpCommandPort = 5351

type PMP struct {
	transport *quic.Transport
	logger    *slog.Logger

	gatewayIP     net.IP
	gatewayAddr   *net.UDPAddr
	localIP       net.IP
	localPort     uint16
	localAddrPort netip.AddrPort

	externalAddr     *notify.V[*netip.Addr]
	externalPort     *notify.V[*uint16]
	externalAddrPort *notify.V[*netip.AddrPort]
}

func NewPMP(transport *quic.Transport, logger *slog.Logger) (*PMP, error) {
	return &PMP{
		transport: transport,
		logger:    logger.With("component", "natpmp"),

		externalAddr:     notify.NewEmpty[*netip.Addr](),
		externalPort:     notify.NewEmpty[*uint16](),
		externalAddrPort: notify.NewEmpty[*netip.AddrPort](),
	}, nil
}

func (s *PMP) Run(ctx context.Context) error {
	var boff netc.SpinBackoff
	for {
		err := s.runGeneration(ctx)
		slogc.Fine(s.logger, "pmp generation completed", "err", err)

		switch {
		case errors.Is(err, context.Canceled):
			return err
		case errors.Is(err, errDiscoverInterface), errors.Is(err, errDiscoverGateway):
			s.logger.Debug("pmp exiting: cannot read interface/gateway", "err", err)
			return nil
		}

		if err := boff.Wait(ctx); err != nil {
			return err
		}
	}
}

var errDiscoverInterface = errors.New("pmp discover interface")
var errDiscoverGateway = errors.New("pmp discover gateway")

func (s *PMP) runGeneration(ctx context.Context) error {
	localIP, err := gateway.DiscoverInterface()
	if err != nil {
		return fmt.Errorf("%w: %w", errDiscoverInterface, err)
	}
	if !localIP.IsPrivate() {
		return fmt.Errorf("pmp interface is not private: %s", localIP)
	}
	s.localIP = localIP

	addr, ok := s.transport.Conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return fmt.Errorf("unexpected local address '%s': %w", s.transport.Conn.LocalAddr(), err)
	}
	s.localPort = uint16(addr.Port)
	s.localAddrPort = netip.AddrPortFrom(netip.AddrFrom4([4]byte(localIP.To4())), s.localPort)

	gatewayIP, err := gateway.DiscoverGateway()
	if err != nil {
		return fmt.Errorf("%w: %w", errDiscoverGateway, err)
	}
	s.gatewayIP = gatewayIP
	s.gatewayAddr = &net.UDPAddr{IP: gatewayIP, Port: pmpCommandPort}

	slogc.Fine(s.logger, "generation start", "gateway", s.gatewayAddr, "local", s.localAddrPort)

	resp, err := retryCall(ctx, func(ctx context.Context) (*pmpDiscoverResponse, error) {
		slogc.Fine(s.logger, "discover external address start", "gateway", s.gatewayAddr)
		resp, err := s.pmpDiscover(ctx)
		if err != nil {
			slogc.Fine(s.logger, "discover external address failed", "gateway", s.gatewayAddr, "err", err)
		} else {
			slogc.Fine(s.logger, "discover external address completed", "gateway", s.gatewayAddr, "external-addr", resp.externalAddr)
		}
		return resp, err
	})
	if err != nil {
		return fmt.Errorf("cannot discover NAT-PMP gateway: %w", err)
	}

	defer s.externalAddr.Set(nil)
	s.externalAddr.Set(&resp.externalAddr)

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return s.notifyExternalAddrPort(ctx)
	})
	g.Go(func() error {
		return s.listenAddressChanges(ctx, resp.epochSeconds)
	})
	g.Go(func() error {
		return s.runMap(ctx)
	})
	return g.Wait()
}

func (s *PMP) Get() []netip.AddrPort {
	addr, err := s.externalAddrPort.Peek()
	if err != nil || addr == nil {
		return nil
	}
	return []netip.AddrPort{*addr, s.localAddrPort}
}

func (s *PMP) Listen(ctx context.Context, fn func([]netip.AddrPort) error) error {
	return s.externalAddrPort.Listen(ctx, func(t *netip.AddrPort) error {
		if t == nil {
			return fn(nil)
		}
		return fn([]netip.AddrPort{*t, s.localAddrPort})
	})
}

func (s *PMP) notifyExternalAddrPort(ctx context.Context) error {
	return notify.ListenMulti(ctx, s.externalAddr, s.externalPort, func(ctx context.Context, addr *netip.Addr, port *uint16) error {
		if addr != nil && port != nil {
			newAddr := netip.AddrPortFrom(*addr, *port)
			s.externalAddrPort.Set(&newAddr)
		} else {
			s.externalAddrPort.Set(nil)
		}
		return nil
	})
}

func (s *PMP) runMap(ctx context.Context) error {
	resp, err := retryCall(ctx, func(ctx context.Context) (*pmpMapResponse, error) {
		slogc.Fine(s.logger, "mapping create start", "gateway", s.gatewayAddr, "local-port", s.localPort)
		resp, err := s.pmpMap(ctx, 0, 60) // TODO change lifetime
		if err != nil {
			slogc.Fine(s.logger, "mapping create failed", "gateway", s.gatewayAddr, "err", err)
		} else {
			slogc.Fine(s.logger, "mapping create completed", "gateway", s.gatewayAddr, "external-port", resp.externalPort)
		}
		return resp, err
	})
	if err != nil {
		return fmt.Errorf("mapping create: %w", err)
	}
	defer func() {
		slogc.Fine(s.logger, "mapping delete", "external-port", resp.externalPort)
		if _, err := s.pmpMap(context.Background(), 0, 0); err != nil {
			slogc.Fine(s.logger, "mapping delete failed", "err", err)
		}
	}()

	defer s.externalPort.Set(nil)

	s.externalPort.Set(&resp.externalPort)
	endOfLife := time.Now().Add(time.Duration(resp.lifetimeSeconds) * time.Second)

	for {
		nextRenew := time.Until(endOfLife) / 2
		if nextRenew <= 0 {
			return fmt.Errorf("mapping renew: timed out")
		}

		slogc.Fine(s.logger, "mapping renew scheduled", "after", nextRenew)
		select {
		case <-time.After(nextRenew):
			renewResp, err := retryCall(ctx, func(ctx context.Context) (*pmpMapResponse, error) {
				slogc.Fine(s.logger, "mapping renew start", "gateway", s.gatewayAddr, "local-port", s.localPort)
				resp, err := s.pmpMap(ctx, resp.externalPort, 60)
				if err != nil {
					slogc.Fine(s.logger, "mapping renew failed", "gateway", s.gatewayAddr, "err", err)
				} else {
					slogc.Fine(s.logger, "mapping renew completed", "gateway", s.gatewayAddr, "external-port", resp.externalPort)
				}
				return resp, err
			})
			if err != nil {
				return fmt.Errorf("mapping renew: %w", err)
			}

			resp = renewResp

			s.externalPort.Set(&resp.externalPort)
			endOfLife = time.Now().Add(time.Duration(resp.lifetimeSeconds) * time.Second)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

var errEpochReset = errors.New("router epoch reset")

func (s *PMP) listenAddressChanges(ctx context.Context, epoch uint32) error {
	var lc net.ListenConfig
	conn, err := lc.ListenPacket(ctx, "udp4", pmpBroadcastAddr)
	if err != nil {
		return err
	}
	defer func() {
		if err := conn.Close(); err != nil {
			slogc.Fine(s.logger, "error closing broadcast listener", "err", err)
		}
	}()

	var readResponse = func(ctx context.Context, buff []byte) (int, net.Addr, error) {
		if err := conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			return 0, nil, err
		}
		defer func() {
			if err := conn.SetReadDeadline(time.Time{}); err != nil {
				slogc.Fine(s.logger, "error resetting deadline", "err", err)
			}
		}()
		return conn.ReadFrom(buff)
	}

	for ctx.Err() == nil {
		resp, err := s.readResponse(ctx, 12, readResponse)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			return fmt.Errorf("could not read packet: %w", err)
		}
		if err := checkResponseHeader(resp, 0); err != nil {
			return fmt.Errorf("discovery check response: %w", err)
		}

		nextEpoch := binary.BigEndian.Uint32(resp[4:])
		externalAddr := netip.AddrFrom4([4]byte(resp[8:12]))

		s.externalAddr.Set(&externalAddr)
		if nextEpoch < epoch {
			return errEpochReset
		}
		epoch = nextEpoch
	}

	return ctx.Err()
}

type pmpDiscoverResponse struct {
	epochSeconds uint32
	externalAddr netip.Addr
}

func (s *PMP) pmpDiscover(ctx context.Context) (*pmpDiscoverResponse, error) {
	request := make([]byte, 2)
	request[0] = 0 // version field
	request[1] = 0 // opcode discover

	if err := s.writeRequest(request); err != nil {
		return nil, fmt.Errorf("discovery write request: %w", err)
	}

	resp, err := s.readResponse(ctx, 12, s.transport.ReadNonQUICPacket)
	if err != nil {
		return nil, fmt.Errorf("discovery read response: %w", err)
	}
	if err := checkResponseHeader(resp, 0); err != nil {
		return nil, fmt.Errorf("discovey check response: %w", err)
	}

	epoch := binary.BigEndian.Uint32(resp[4:])
	externalAddr := netip.AddrFrom4([4]byte(resp[8:12]))
	return &pmpDiscoverResponse{epoch, externalAddr}, nil
}

type pmpMapResponse struct {
	epochSeconds    uint32
	externalPort    uint16
	lifetimeSeconds uint32
}

func (s *PMP) pmpMap(ctx context.Context, desiredExternalPort uint16, mappingLifetimeSeconds int32) (*pmpMapResponse, error) {
	request := make([]byte, 12)
	request[0] = 0 // version field
	request[1] = 1 // opcode, map UDP
	// request[2] + request[3] are reserved, 0
	binary.BigEndian.PutUint16(request[4:], s.localPort)
	binary.BigEndian.PutUint16(request[6:], uint16(desiredExternalPort))
	binary.BigEndian.PutUint32(request[8:], uint32(mappingLifetimeSeconds))

	if err := s.writeRequest(request); err != nil {
		return nil, fmt.Errorf("map write request: %w", err)
	}

	resp, err := s.readResponse(ctx, 16, s.transport.ReadNonQUICPacket)
	if err != nil {
		return nil, fmt.Errorf("map read response: %w", err)
	}
	if err := checkResponseHeader(resp, 1); err != nil {
		return nil, fmt.Errorf("map check response: %w", err)
	}

	epoch := binary.BigEndian.Uint32(resp[4:])
	respInternalPort := binary.BigEndian.Uint16(resp[8:])
	if respInternalPort != s.localPort {
		return nil, fmt.Errorf("map internal port mismatch")
	}
	respMappedPort := binary.BigEndian.Uint16(resp[10:])
	respLifetime := binary.BigEndian.Uint32(resp[12:])

	return &pmpMapResponse{epochSeconds: epoch, externalPort: respMappedPort, lifetimeSeconds: respLifetime}, nil
}

func (s *PMP) writeRequest(request []byte) error {
	n, err := s.transport.WriteTo(request, s.gatewayAddr)
	if err != nil {
		return fmt.Errorf("cannot write packet: %w", err)
	} else if n < len(request) {
		return fmt.Errorf("unexpected request write size")
	}
	return nil
}

var errRetryFailed = errors.New("retry failed: timeout")

func retryCall[T any](ctx context.Context, fn func(ctx context.Context) (T, error)) (T, error) {
	timeout := 250 * time.Millisecond
	for range 9 {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		resp, err := fn(ctx)
		switch {
		case err == nil:
			return resp, nil
		case errors.Is(err, context.DeadlineExceeded):
			timeout = 2 * timeout
		default:
			return resp, err
		}
	}
	var t T
	return t, errRetryFailed
}

type readerFn = func(context.Context, []byte) (int, net.Addr, error)

func (s *PMP) readResponse(ctx context.Context, expectedSize int, rdr readerFn) ([]byte, error) {
	resp := make([]byte, 16)
	m, respAddr, err := rdr(ctx, resp)
	if err != nil {
		return nil, fmt.Errorf("could not read packet: %w", err)
	}
	if m != expectedSize {
		return nil, fmt.Errorf("unexpected packet size")
	}

	switch t := respAddr.(type) {
	case *net.UDPAddr:
		if !s.gatewayIP.Equal(t.IP) {
			return nil, fmt.Errorf("unexpected response udp address: %s", t.IP)
		}
	case *net.TCPAddr:
		if !s.gatewayIP.Equal(t.IP) {
			return nil, fmt.Errorf("unexpected response tcp address: %s", t.IP)
		}
	default:
		return nil, fmt.Errorf("unexpected response address type: %t", t)
	}

	return resp[0:m], nil
}

var errPMPUnsupportedVersion = errors.New("nat-pmp - unsupported version")
var errPMPNotAuthorized = errors.New("nat-pmp - not authorized")
var errPMPNetworkFailure = errors.New("nat-pmp - network failure")
var errPMPOutOfResource = errors.New("nat-pmp - out of resource")
var errPMPUnsupportedOpcode = errors.New("nat-pmp - unsupported opcode")
var errPMPUnknownError = errors.New("nat-pmp - unknown error")

func checkResponseHeader(resp []byte, opcode byte) error {
	if resp[0] != 0 {
		return fmt.Errorf("nat-pmp - version mismatch: %d", resp[0])
	}
	if resp[1] != 128+opcode {
		return fmt.Errorf("nat-pmp - unexpected response opcode: %d", resp[1])
	}
	resultCode := binary.BigEndian.Uint16(resp[2:])
	switch resultCode {
	case 0:
		return nil
	case 1:
		return errPMPUnsupportedVersion
	case 2:
		return errPMPNotAuthorized
	case 3:
		return errPMPNetworkFailure
	case 4:
		return errPMPOutOfResource
	case 5:
		return errPMPUnsupportedOpcode
	default:
		return errPMPUnknownError
	}
}
