package nat

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/connet-dev/connet/pkg/notify"
	"github.com/connet-dev/connet/pkg/reliable"
	"github.com/connet-dev/connet/pkg/slogc"
	"github.com/jackpal/gateway"
	"github.com/quic-go/quic-go"
)

type PCPConfig struct {
	Disabled        bool
	LocalResolver   LocalIPResolver
	GatewayResolver GatewayIPResolver
}

const pcpLifetime = 10 * 60 // 10 minutes

type PCP struct {
	PCPConfig
	transport *quic.Transport
	localPort uint16
	nonce     [12]byte

	gatewayIP   net.IP
	gatewayAddr *net.UDPAddr
	localIP     net.IP
	localAddrPort netip.AddrPort
	epoch       *epochTracker

	externalAddr     *notify.V[*netip.Addr]
	externalPort     *notify.V[*uint16]
	externalAddrPort *notify.V[*netip.AddrPort]

	logger *slog.Logger
}

func NewPCP(cfg PCPConfig, transport *quic.Transport, localPort uint16, logger *slog.Logger) *PCP {
	p := &PCP{
		PCPConfig: cfg,
		transport: transport,
		localPort: localPort,

		externalAddr:     notify.NewEmpty[*netip.Addr](),
		externalPort:     notify.NewEmpty[*uint16](),
		externalAddrPort: notify.NewEmpty[*netip.AddrPort](),

		logger: logger.With("component", "natpcp"),
	}
	if _, err := rand.Read(p.nonce[:]); err != nil {
		panic(fmt.Sprintf("pcp: generate nonce: %v", err))
	}
	return p
}

func (s *PCP) Get() []netip.AddrPort {
	if s.Disabled {
		return nil
	}

	addr, ok := s.externalAddrPort.Peek()
	if !ok || addr == nil {
		return nil
	}
	return []netip.AddrPort{*addr, s.localAddrPort}
}

func (s *PCP) Listen(ctx context.Context, fn func([]netip.AddrPort) error) error {
	if s.Disabled {
		return nil
	}

	return s.externalAddrPort.Listen(ctx, func(t *netip.AddrPort) error {
		if t == nil {
			return fn(nil)
		}
		return fn([]netip.AddrPort{*t, s.localAddrPort})
	})
}

func (s *PCP) Run(ctx context.Context) error {
	if s.Disabled {
		return nil
	}

	boff := reliable.SpinBackoff{MinBackoff: time.Second, MaxBackoff: time.Minute}
	for {
		err := s.runGeneration(ctx)
		s.logger.Debug("pcp generation completed", "err", err)

		switch {
		case errors.Is(err, context.Canceled):
			return err
		case errors.Is(err, &gateway.ErrNoGateway{}):
			// did not find gateway
		case errors.Is(err, errDiscoverInterface), errors.Is(err, errDiscoverGateway):
			s.logger.Debug("pcp exiting: cannot read interface/gateway", "err", err)
			return nil
		}

		if err := boff.Wait(ctx); err != nil {
			return err
		}
	}
}

func (s *PCP) runGeneration(ctx context.Context) error {
	localIP, err := s.waitInterface(ctx)
	if err != nil {
		return err
	}
	s.localIP = localIP
	s.localAddrPort = netip.AddrPortFrom(netip.AddrFrom4([4]byte(localIP.To4())), s.localPort)

	gatewayIP, err := s.GatewayResolver(ctx, localIP)
	if err != nil {
		return fmt.Errorf("%w: %w", errDiscoverGateway, err)
	}
	s.gatewayIP = gatewayIP
	s.gatewayAddr = &net.UDPAddr{IP: gatewayIP, Port: pmpCommandPort}

	s.logger.Debug("generation start", "gateway", s.gatewayAddr, "local", s.localAddrPort)

	resp0, err := retryCall(ctx, func(ctx context.Context) (*pcpMapResponse, error) {
		slogc.Fine(s.logger, "mapping create start", "gateway", s.gatewayAddr, "local-port", s.localPort)
		resp, err := s.pcpMap(ctx, 0, netip.Addr{}, pcpLifetime)
		if err != nil {
			slogc.Fine(s.logger, "mapping create failed", "gateway", s.gatewayAddr, "err", err)
		} else {
			slogc.Fine(s.logger, "mapping create completed", "gateway", s.gatewayAddr,
				"epoch", resp.epochSeconds, "external-addr", resp.externalAddr,
				"external-port", resp.externalPort, "lifetime", resp.lifetimeSeconds)
		}
		return resp, err
	})
	if err != nil {
		return fmt.Errorf("cannot map PCP: %w", err)
	}

	s.externalAddr.Set(&resp0.externalAddr)
	defer s.externalAddr.Set(nil)

	s.epoch = &epochTracker{at: time.Now(), seconds: resp0.epochSeconds, logger: s.logger}
	defer func() { s.epoch = nil }()

	runMap := func(ctx context.Context) error {
		defer func() {
			slogc.Fine(s.logger, "mapping delete", "external-addr", resp0.externalAddr, "external-port", resp0.externalPort)
			dctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			if _, err := s.pcpMap(dctx, 0, netip.Addr{}, 0); err != nil {
				slogc.Fine(s.logger, "mapping delete failed", "err", err)
			}
		}()

		s.externalPort.Set(&resp0.externalPort)
		defer s.externalPort.Set(nil)

		if err := s.epoch.Update(resp0.epochSeconds); err != nil {
			return fmt.Errorf("mapping create - epoch reset: %w", err)
		}

		resp := resp0
		endOfLife := time.Now().Add(time.Duration(resp.lifetimeSeconds) * time.Second)

		for {
			nextRenew := time.Until(endOfLife) / 2
			if nextRenew <= 0 {
				return fmt.Errorf("mapping renew: timed out")
			}

			slogc.Fine(s.logger, "mapping renew scheduled", "after", nextRenew)
			select {
			case <-time.After(nextRenew):
				renewResp, err := retryCall(ctx, func(ctx context.Context) (*pcpMapResponse, error) {
					slogc.Fine(s.logger, "mapping renew start", "gateway", s.gatewayAddr, "local-port", s.localPort)
					r, err := s.pcpMap(ctx, resp.externalPort, resp.externalAddr, pcpLifetime)
					if err != nil {
						slogc.Fine(s.logger, "mapping renew failed", "gateway", s.gatewayAddr, "err", err)
					} else {
						slogc.Fine(s.logger, "mapping renew completed", "gateway", s.gatewayAddr,
							"epoch", r.epochSeconds, "external-addr", r.externalAddr,
							"external-port", r.externalPort, "lifetime", r.lifetimeSeconds)
					}
					return r, err
				})
				if err != nil {
					return fmt.Errorf("mapping renew: %w", err)
				}
				resp = renewResp
				s.externalPort.Set(&resp.externalPort)
				if err := s.epoch.Update(resp.epochSeconds); err != nil {
					return fmt.Errorf("mapping renew - epoch reset: %w", err)
				}
				endOfLife = time.Now().Add(time.Duration(resp.lifetimeSeconds) * time.Second)
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}

	return reliable.RunGroup(ctx,
		s.notifyExternalAddrPort,
		s.pcpListenAddressChange,
		s.resolverListenAddressChange,
		runMap,
	)
}

func (s *PCP) waitInterface(ctx context.Context) (net.IP, error) {
	for {
		localIP, err := s.LocalResolver(ctx)
		if err != nil {
			return net.IPv4zero, err
		}
		if localIP.IsPrivate() {
			return localIP, nil
		}
		if err := reliable.Wait(ctx, 10*time.Second); err != nil {
			return net.IPv4zero, err
		}
	}
}

func (s *PCP) notifyExternalAddrPort(ctx context.Context) error {
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

func (s *PCP) resolverListenAddressChange(ctx context.Context) error {
	for {
		nextIP, err := s.LocalResolver(ctx)
		if err == nil && !s.localIP.Equal(nextIP) {
			return errLocalAddressChanged
		}
		if err := reliable.Wait(ctx, 10*time.Second); err != nil {
			return err
		}
	}
}

func (s *PCP) pcpListenAddressChange(ctx context.Context) error {
	var lc net.ListenConfig
	conn, err := lc.ListenPacket(ctx, "udp4", pmpBroadcastAddr)
	if err != nil {
		s.logger.Debug("pcp broadcast listen failed, skipping", "err", err)
		<-ctx.Done()
		return ctx.Err()
	}
	defer func() {
		if err := conn.Close(); err != nil {
			slogc.Fine(s.logger, "error closing broadcast listener", "err", err)
		}
	}()

	readResponse := func(ctx context.Context, buff []byte) (int, net.Addr, error) {
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
		// PCP ANNOUNCE response is 24 bytes (opcode 0)
		resp, err := s.readResponse(ctx, 24, 0, readResponse)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			return fmt.Errorf("could not read packet: %w", err)
		}

		nextEpoch := binary.BigEndian.Uint32(resp[8:12])
		if err := s.epoch.Update(nextEpoch); err != nil {
			return fmt.Errorf("pcp listen change - epoch reset: %w", err)
		}
	}

	return ctx.Err()
}

type pcpMapResponse struct {
	epochSeconds    uint32
	externalAddr    netip.Addr
	externalPort    uint16
	lifetimeSeconds uint32
}

func (s *PCP) pcpMap(ctx context.Context, desiredExternalPort uint16, desiredExternalAddr netip.Addr, lifetime int32) (*pcpMapResponse, error) {
	request := make([]byte, 60)
	request[0] = 2    // version
	request[1] = 0x01 // R=0, opcode=MAP
	// [2:4] reserved = 0
	binary.BigEndian.PutUint32(request[4:], uint32(lifetime))
	// [8:24] client IP as IPv4-mapped IPv6: 10×0x00 + 0xFF 0xFF + 4-byte IPv4
	localIP4 := s.localIP.To4()
	// request[8:18] already zero
	request[18] = 0xFF
	request[19] = 0xFF
	copy(request[20:24], localIP4)
	// [24:36] nonce
	copy(request[24:36], s.nonce[:])
	// [36] = 17 (UDP)
	request[36] = 17
	// [37:40] reserved = 0
	// [40:42] internal port
	binary.BigEndian.PutUint16(request[40:], s.localPort)
	// [42:44] suggested external port
	binary.BigEndian.PutUint16(request[42:], desiredExternalPort)
	// [44:60] suggested external IP (all zeros = any)
	if desiredExternalAddr.IsValid() {
		if desiredExternalAddr.Is4() {
			ip4 := desiredExternalAddr.As4()
			// write as IPv4-mapped IPv6
			request[54] = 0xFF
			request[55] = 0xFF
			copy(request[56:60], ip4[:])
		} else {
			ip6 := desiredExternalAddr.As16()
			copy(request[44:60], ip6[:])
		}
	}

	if err := s.writeRequest(request); err != nil {
		return nil, fmt.Errorf("map write request: %w", err)
	}
	resp, err := s.readResponse(ctx, 60, 1, s.transport.ReadNonQUICPacket)
	if err != nil {
		return nil, fmt.Errorf("map read response: %w", err)
	}

	lifetimeSeconds := binary.BigEndian.Uint32(resp[4:8])
	epochSeconds := binary.BigEndian.Uint32(resp[8:12])
	respInternalPort := binary.BigEndian.Uint16(resp[40:42])
	if respInternalPort != s.localPort {
		return nil, fmt.Errorf("pcp map internal port mismatch: got %d, want %d", respInternalPort, s.localPort)
	}
	externalPort := binary.BigEndian.Uint16(resp[42:44])
	externalAddr := extractIPv4MappedOrIPv6(resp[44:60])

	return &pcpMapResponse{
		epochSeconds:    epochSeconds,
		externalAddr:    externalAddr,
		externalPort:    externalPort,
		lifetimeSeconds: lifetimeSeconds,
	}, nil
}

func (s *PCP) writeRequest(request []byte) error {
	n, err := s.transport.WriteTo(request, s.gatewayAddr)
	if err != nil {
		return fmt.Errorf("cannot write packet: %w", err)
	} else if n < len(request) {
		return fmt.Errorf("unexpected request write size")
	}
	return nil
}

func (s *PCP) readResponse(ctx context.Context, expectedSize int, expectedOpcode byte, rdr readerFn) ([]byte, error) {
	resp := make([]byte, 64)
	m, respAddr, err := rdr(ctx, resp)
	if err != nil {
		return nil, fmt.Errorf("could not read packet: %w", err)
	}
	if m != expectedSize {
		return nil, fmt.Errorf("unexpected packet size: got %d, want %d", m, expectedSize)
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
		return nil, fmt.Errorf("unexpected response address type: %T", t)
	}

	resp = resp[:m]
	if err := checkPCPResponseHeader(resp, expectedOpcode); err != nil {
		return nil, err
	}

	return resp, nil
}

var errPCPUnsuppVersion        = errors.New("pcp - unsupported version")
var errPCPNotAuthorized        = errors.New("pcp - not authorized")
var errPCPMalformedRequest     = errors.New("pcp - malformed request")
var errPCPUnsuppOpcode         = errors.New("pcp - unsupported opcode")
var errPCPUnsuppOption         = errors.New("pcp - unsupported option")
var errPCPMalformedOption      = errors.New("pcp - malformed option")
var errPCPNetworkFailure       = errors.New("pcp - network failure")
var errPCPNoResources          = errors.New("pcp - no resources")
var errPCPUnsuppProtocol       = errors.New("pcp - unsupported protocol")
var errPCPUserExQuota          = errors.New("pcp - user exceeded quota")
var errPCPCannotProvideExternal = errors.New("pcp - cannot provide external")
var errPCPAddressMismatch      = errors.New("pcp - address mismatch")
var errPCPExcessiveRemotePeers = errors.New("pcp - excessive remote peers")

func checkPCPResponseHeader(resp []byte, opcode byte) error {
	if resp[0] != 2 {
		return fmt.Errorf("pcp - version mismatch: %d", resp[0])
	}
	if resp[1] != 0x80|opcode {
		return fmt.Errorf("pcp - unexpected response opcode: %d", resp[1])
	}
	switch resp[3] {
	case 0:
		return nil
	case 1:
		return errPCPUnsuppVersion
	case 2:
		return errPCPNotAuthorized
	case 3:
		return errPCPMalformedRequest
	case 4:
		return errPCPUnsuppOpcode
	case 5:
		return errPCPUnsuppOption
	case 6:
		return errPCPMalformedOption
	case 7:
		return errPCPNetworkFailure
	case 8:
		return errPCPNoResources
	case 9:
		return errPCPUnsuppProtocol
	case 10:
		return errPCPUserExQuota
	case 11:
		return errPCPCannotProvideExternal
	case 12:
		return errPCPAddressMismatch
	case 13:
		return errPCPExcessiveRemotePeers
	default:
		return fmt.Errorf("pcp - unknown result code: %d", resp[3])
	}
}

func extractIPv4MappedOrIPv6(b []byte) netip.Addr {
	// IPv4-mapped IPv6: first 10 bytes are 0, bytes 10-11 are 0xFF 0xFF
	allZero := true
	for _, byt := range b[:10] {
		if byt != 0 {
			allZero = false
			break
		}
	}
	if allZero && b[10] == 0xFF && b[11] == 0xFF {
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	}
	return netip.AddrFrom16([16]byte(b[:16]))
}
