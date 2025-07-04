package nat

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

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

	gatewayIP   net.IP
	gatewayAddr *net.UDPAddr
	localIP     net.IP
	localPort   uint16

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
	gwIP, err := gateway.DiscoverGateway()
	if err != nil {
		return fmt.Errorf("discover network gateway: %w", err)
	}
	s.gatewayIP = gwIP
	s.gatewayAddr = &net.UDPAddr{IP: gwIP, Port: pmpCommandPort}

	myIP, err := gateway.DiscoverInterface()
	if err != nil {
		return fmt.Errorf("discover network interface: %w", err)
	}
	s.localIP = myIP

	addr, ok := s.transport.Conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return fmt.Errorf("unexpected local address '%s': %w", s.transport.Conn.LocalAddr(), err)
	}
	s.localPort = uint16(addr.Port)

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return s.notifyExternalAddrPort(ctx)
	})
	g.Go(func() error {
		return s.runDiscovery(ctx)
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
	return []netip.AddrPort{*addr}
}

func (s *PMP) Listen(ctx context.Context, fn func([]netip.AddrPort) error) error {
	return s.externalAddrPort.Listen(ctx, func(t *netip.AddrPort) error {
		if t == nil {
			return fn(nil)
		}
		return fn([]netip.AddrPort{*t})
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

func (s *PMP) runDiscovery(ctx context.Context) error {
	defer s.externalAddr.Set(nil)

	resp, err := retryCall(ctx, s.pmpDiscover)
	if err != nil {
		return err
	}
	s.externalAddr.Set(&resp.externalAddr)

	return s.listenAddressChanges(ctx, resp.epochSeconds)
}

func (s *PMP) runMap(ctx context.Context) error {
	defer s.externalPort.Set(nil)

	resp, err := retryCall(ctx, func(ctx context.Context) (*pmpMapResponse, error) {
		return s.pmpMap(ctx, 0, 60) // TODO change lifetime
	})
	if err != nil {
		return err
	}
	s.externalPort.Set(&resp.externalPort)

	for {
		select {
		case <-time.After(time.Duration(resp.lifetimeSeconds) * time.Second / 2):
			resp, err = retryCall(ctx, func(ctx context.Context) (*pmpMapResponse, error) {
				return s.pmpMap(ctx, resp.externalPort, 60)
			})
			if err != nil {
				return err
			}
		case <-ctx.Done():
			_, merr := s.pmpMap(context.Background(), 0, 0)
			return errors.Join(err, merr)
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
		return conn.ReadFrom(buff)
	}

	for {
		resp, err := s.readResponse(ctx, 12, readResponse)
		if err != nil {
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

func retryCall[T any](ctx context.Context, fn func(ctx context.Context) (T, error)) (T, error) {
	var errs []error
	for i := range 9 {
		timeout := time.Duration(250*i) * time.Millisecond
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		resp, err := fn(ctx)
		if err == nil {
			return resp, nil
		}
		errs = append(errs, err)
	}

	var t T
	return t, errors.Join(errs...)
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
		return fmt.Errorf("nat-pmp - unsupported version")
	case 2:
		return fmt.Errorf("nat-pmp - not authorized")
	case 3:
		return fmt.Errorf("nat-pmp - network failure")
	case 4:
		return fmt.Errorf("nat-pmp - out of resource")
	case 5:
		return fmt.Errorf("nat-pmp - unsupported opcode")
	default:
		return fmt.Errorf("nat-pmp - unknown error")
	}
}
