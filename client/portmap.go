package client

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	"github.com/connet-dev/connet/netc"
	"github.com/jackpal/gateway"
	"github.com/quic-go/quic-go"
)

const pmpBroadcastPort = 5350
const pmpCommandPort = 5351

type Portmapper struct {
	transport *quic.Transport
	logger    *slog.Logger

	gatewayIP net.IP
	localIP   net.IP
}

func NewPortmapper(transport *quic.Transport, logger *slog.Logger) (*Portmapper, error) {
	gwIP, err := gateway.DiscoverGateway()
	if err != nil {
		return nil, err
	}
	myIP, err := gateway.DiscoverInterface()
	if err != nil {
		return nil, err
	}

	return &Portmapper{
		transport: transport,
		logger:    logger.With("component", "portmapper"),

		gatewayIP: gwIP,
		localIP:   myIP,
	}, nil
}

func (s *Portmapper) Run(ctx context.Context) error {
	return nil
}

type pmpDiscoverData struct {
	epochSeconds uint32
	externalAddr netip.Addr
}

func (s *Portmapper) pmpDiscover(ctx context.Context) (*pmpDiscoverData, error) {
	var targetAddr = &net.UDPAddr{IP: s.gatewayIP, Port: pmpCommandPort}
	var request = [2]byte{
		0, // version field
		0, // opcode field
	}
	n, err := s.transport.WriteTo(request[:], targetAddr)
	if err != nil {
		return nil, fmt.Errorf("could not write discovery packet: %w", err)
	} else if n < len(request) {
		return nil, fmt.Errorf("unexpected check request write size")
	}

	var resp = make([]byte, 1100)
	m, resAddr, err := s.transport.ReadNonQUICPacket(ctx, resp)
	if err != nil {
		return nil, fmt.Errorf("could not read discovery packet: %w", err)
	}
	resNetip, err := netc.AddrPortFromNet(resAddr)
	if err != nil {
		return nil, fmt.Errorf("could not extract addr: %w", err)
	}
	if resNetip.Addr() != netip.AddrFrom4([4]byte(s.gatewayIP.To4())) {
		return nil, fmt.Errorf("gw address mismatch: %s", resNetip)
	}
	if m < 12 {
		return nil, fmt.Errorf("nat-pmp: unexpected response length: %d", m)
	}

	if err := checkResponseHeader(resp, 0); err != nil {
		return nil, err
	}

	epoch := binary.BigEndian.Uint32(resp[4:])
	externalAddr := netip.AddrFrom4([4]byte(resp[8:12]))
	return &pmpDiscoverData{epoch, externalAddr}, nil
}

type pmpMapData struct {
	epochSeconds    uint32
	externalPort    uint16
	lifetimeSeconds uint32
}

func (s *Portmapper) pmpMap(ctx context.Context,
	internalPort uint16, desiredExternalPort uint16, mappingLifetimeSeconds int32,
) (*pmpMapData, error) {
	var targetAddr = &net.UDPAddr{IP: s.gatewayIP, Port: pmpCommandPort}

	request := make([]byte, 12)
	request[0] = 0 // version field
	request[1] = 1 // opcode, map UDP
	// request[2] + request[3] are reserved, 0
	binary.BigEndian.PutUint16(request[4:], uint16(internalPort))
	binary.BigEndian.PutUint16(request[6:], uint16(desiredExternalPort))
	binary.BigEndian.PutUint32(request[8:], uint32(mappingLifetimeSeconds))

	n, err := s.transport.WriteTo(request, targetAddr)
	if err != nil {
		return nil, fmt.Errorf("could not write discovery packet: %w", err)
	} else if n < len(request) {
		return nil, fmt.Errorf("unexpected check request write size")
	}

	var resp = make([]byte, 1100)
	m, resAddr, err := s.transport.ReadNonQUICPacket(ctx, resp)
	if err != nil {
		return nil, fmt.Errorf("could not read discovery packet: %w", err)
	}
	resNetip, err := netc.AddrPortFromNet(resAddr)
	if err != nil {
		return nil, fmt.Errorf("could not extract addr: %w", err)
	}
	if resNetip.Addr() != netip.AddrFrom4([4]byte(s.gatewayIP.To4())) {
		return nil, fmt.Errorf("gw address mismatch: %s", resNetip)
	}
	if m < 16 {
		return nil, fmt.Errorf("nat-pmp: unexpected response length: %d", m)
	}

	if err := checkResponseHeader(resp, 1); err != nil {
		return nil, err
	}

	epoch := binary.BigEndian.Uint32(resp[4:])
	respInternalPort := binary.BigEndian.Uint16(resp[8:])
	if respInternalPort != internalPort {
		return nil, fmt.Errorf("internal port mismatch")
	}
	respMappedPort := binary.BigEndian.Uint16(resp[10:])
	respLifetime := binary.BigEndian.Uint32(resp[12:])

	return &pmpMapData{epochSeconds: epoch, externalPort: respMappedPort, lifetimeSeconds: respLifetime}, nil
}

func checkResponseHeader(resp []byte, opcode byte) error {
	if resp[0] != 0 {
		return fmt.Errorf("nat-pmp: version mismatch: %d", resp[0])
	}
	if resp[1] != 128+opcode {
		return fmt.Errorf("nat-pmp: unexpected response opcode: %d", resp[1])
	}
	resultCode := binary.BigEndian.Uint16(resp[2:])
	switch resultCode {
	case 0:
		return nil
	case 1:
		return fmt.Errorf("nat-pmp: unsupported version")
	case 2:
		return fmt.Errorf("nat-pmp: not authorized")
	case 3:
		return fmt.Errorf("nat-pmp: network failure")
	case 4:
		return fmt.Errorf("nat-pmp: out of resource")
	case 5:
		return fmt.Errorf("nat-pmp: unsupported opcode")
	default:
		return fmt.Errorf("nat-pmp: unknown error")
	}
}
