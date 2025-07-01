package client

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	"github.com/jackpal/gateway"
	"github.com/quic-go/quic-go"
)

const pmpBroadcastPort = 5350
const pmpCommandPort = 5351

type Portmapper struct {
	transport *quic.Transport
	logger    *slog.Logger

	gatewayIP   net.IP
	gatewayAddr *net.UDPAddr
	localIP     net.IP
	localPort   uint16
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

	addr, ok := transport.Conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, fmt.Errorf("unexpected local address: %s", transport.Conn.LocalAddr())
	}

	return &Portmapper{
		transport: transport,
		logger:    logger.With("component", "portmapper"),

		gatewayIP:   gwIP,
		gatewayAddr: &net.UDPAddr{IP: gwIP, Port: pmpCommandPort},
		localIP:     myIP,
		localPort:   uint16(addr.Port),
	}, nil
}

func (s *Portmapper) Run(ctx context.Context) error {
	return nil
}

type pmpDiscoverResponse struct {
	epochSeconds uint32
	externalAddr netip.Addr
}

func (s *Portmapper) pmpDiscover(ctx context.Context) (*pmpDiscoverResponse, error) {
	request := make([]byte, 2)
	request[0] = 0 // version field
	request[1] = 0 // opcode discover

	if err := s.writeRequest(request); err != nil {
		return nil, fmt.Errorf("discovery write request: %w", err)
	}

	resp, err := s.readResponse(ctx, 12)
	if err != nil {
		return nil, fmt.Errorf("discovery read response: %w", err)
	}
	if err := checkResponseHeader(resp, 0); err != nil {
		return nil, fmt.Errorf("discovey check response: %w:", err)
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

func (s *Portmapper) pmpMap(ctx context.Context, desiredExternalPort uint16, mappingLifetimeSeconds int32) (*pmpMapResponse, error) {
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

	resp, err := s.readResponse(ctx, 16)
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

func (s *Portmapper) writeRequest(request []byte) error {
	n, err := s.transport.WriteTo(request, s.gatewayAddr)
	if err != nil {
		return fmt.Errorf("cannot write packet: %w", err)
	} else if n < len(request) {
		return fmt.Errorf("unexpected request write size")
	}
	return nil
}

func (s *Portmapper) readResponse(ctx context.Context, expectedSize int) ([]byte, error) {
	resp := make([]byte, 16)
	m, respAddr, err := s.transport.ReadNonQUICPacket(ctx, resp)
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
