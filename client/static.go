package client

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/proto/pbclient"
	"github.com/connet-dev/connet/proto/pbmodel"
	"github.com/connet-dev/connet/proto/pbstatic"
	"github.com/mr-tron/base58"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
)

type StaticConfig struct {
	Addrs           []string
	LocalPrivateKey [32]byte
	RemotePublicKey [32]byte
}

type staticPeer struct {
	ep             model.Endpoint
	cfg            StaticConfig
	peer           *peer
	localPublicKey [32]byte

	// localRemoteHasher      hash.Hash
	// remoteLocalHasher      hash.Hash
	localRemoteEndpoint    []byte
	remoteLocalEndpoint    []byte
	localRemoteEndpointEnc string
	remoteLocalEndpointEnc string

	logger *slog.Logger
}

func newStaticPeer(ep model.Endpoint, cfg StaticConfig, peer *peer, logger *slog.Logger) *staticPeer {
	p := &staticPeer{ep: ep, cfg: cfg, peer: peer, logger: logger.With("component", "static")}
	curve25519.ScalarBaseMult(&p.localPublicKey, &p.cfg.LocalPrivateKey)

	localRemoteHasher := hmac.New(sha256.New, append(p.localPublicKey[:], cfg.RemotePublicKey[:]...))
	remoteLocalHasher := hmac.New(sha256.New, append(cfg.RemotePublicKey[:], p.localPublicKey[:]...))
	p.localRemoteEndpoint = localRemoteHasher.Sum([]byte(ep.String()))
	p.remoteLocalEndpoint = remoteLocalHasher.Sum([]byte(ep.String()))
	p.localRemoteEndpointEnc = base58.Encode(p.localRemoteEndpoint)
	p.remoteLocalEndpointEnc = base58.Encode(p.remoteLocalEndpoint)

	return p
}

func (s *staticPeer) run(ctx context.Context) error {
	if len(s.cfg.Addrs) == 0 {
		return s.runServer(ctx)
	}

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error { return s.runClient(ctx) })
	g.Go(func() error { return s.runServer(ctx) })
	return g.Wait()
}

func (s *staticPeer) runServer(ctx context.Context) error {
	for {
		ch := s.peer.direct.expectStatic(s.remoteLocalEndpointEnc)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case pr := <-ch:
			peer, err := s.decryptPeer(pr.peer)
			if err != nil {
				return fmt.Errorf("could not decrypt response peer: %w", err)
			}

			paddr, err := pbmodel.AddrPortFromNet(pr.addr)
			if err != nil {
				return fmt.Errorf("could not parse: %w", err)
			}
			peer.Directs = append(peer.Directs, paddr)

			s.peer.addStaticPeer(&pbclient.RemotePeer{
				Id:   fmt.Sprintf("%s-server", s.remoteLocalEndpointEnc),
				Peer: peer,
			})

			resp, err := s.makeResponse()
			if err != nil {
				return fmt.Errorf("could not make response: %w", err)
			}
			n, err := s.peer.direct.transport.WriteTo(resp, pr.addr)
			if err != nil {
				return fmt.Errorf("could not write direct: %w", err)
			}
			if n < len(resp) {
				return fmt.Errorf("invalid size: %d expected %d", n, len(resp))
			}
		}

	}
}

func (s *staticPeer) runClient(ctx context.Context) error {
	return s.clientConnect(ctx)
}

func (s *staticPeer) clientConnect(ctx context.Context) error {
	var merr []error
	for _, saddr := range s.cfg.Addrs {
		addr, err := net.ResolveUDPAddr("udp", saddr)
		if err != nil {
			merr = append(merr, fmt.Errorf("resolve addr: %w", err))
			continue
		}

		req, err := s.makeRequest()
		if err != nil {
			merr = append(merr, fmt.Errorf("make request: %w", err))
			continue
		}

		s.logger.Debug("sending client request", "addr", addr)
		if n, err := s.peer.direct.transport.WriteTo(req, addr); err != nil {
			merr = append(merr, fmt.Errorf("write direct: %w", err))
			continue
		} else if n < len(req) {
			merr = append(merr, fmt.Errorf("write size: %d expected %d", n, len(req)))
			continue
		}

		ch := s.peer.direct.expectStatic(s.remoteLocalEndpointEnc)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(15 * time.Second):
			s.peer.direct.unexpectStatic(s.remoteLocalEndpointEnc)
			merr = append(merr, fmt.Errorf("timed out waiting for response from %s", addr))
			continue
		case pr := <-ch:
			peer, err := s.decryptPeer(pr.peer)
			if err != nil {
				return fmt.Errorf("could not decrypt response peer: %w", err)
			}

			paddr, err := pbmodel.AddrPortFromNet(pr.addr)
			if err != nil {
				return fmt.Errorf("could not parse: %w", err)
			}
			peer.Directs = append(peer.Directs, paddr)

			s.peer.addStaticPeer(&pbclient.RemotePeer{
				Id:   fmt.Sprintf("%s-client", s.localRemoteEndpointEnc),
				Peer: peer,
			})
			// TODO send back the response
		}
	}
	return nil
}

func (s *staticPeer) encryptLocalPeer() ([]byte, error) {
	peerData, err := proto.Marshal(&pbclient.Peer{
		// TODO directs
		ServerCertificate: s.peer.serverCert.Leaf.Raw,
		ClientCertificate: s.peer.clientCert.Leaf.Raw,
	})
	if err != nil {
		return nil, fmt.Errorf("could not marshal peer: %w", err)
	}

	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, fmt.Errorf("could not read nonce: %w", err)
	}

	return box.Seal(nonce[:], peerData, &nonce, &s.cfg.RemotePublicKey, &s.cfg.LocalPrivateKey), nil
}

func (s *staticPeer) decryptPeer(encrypted []byte) (*pbclient.Peer, error) {
	var decryptNonce [24]byte
	copy(decryptNonce[:], encrypted[:24])

	decrypted, ok := box.Open(nil, encrypted[24:], &decryptNonce, &s.cfg.RemotePublicKey, &s.cfg.LocalPrivateKey)
	if !ok {
		return nil, fmt.Errorf("could not decrypt peer")
	}
	peer := &pbclient.Peer{}
	if err := proto.Unmarshal(decrypted, peer); err != nil {
		return nil, fmt.Errorf("could not unmarshal peer: %w", err)
	}
	return peer, nil
}

func (s *staticPeer) makeRequest() ([]byte, error) {
	peerData, err := s.encryptLocalPeer()
	if err != nil {
		return nil, fmt.Errorf("could not encrypt request peer: %w", err)
	}

	data, err := proto.Marshal(&pbstatic.Message{
		Target: s.localRemoteEndpoint,
		Data:   peerData,
	})
	if err != nil {
		return nil, fmt.Errorf("could not marshal request: %w", err)
	}

	return append([]byte{0x0c}, data...), nil
}

func (s *staticPeer) makeResponse() ([]byte, error) {
	peerData, err := s.encryptLocalPeer()
	if err != nil {
		return nil, fmt.Errorf("could not encrypt response peer: %w", err)
	}

	data, err := proto.Marshal(&pbstatic.Message{
		Target: s.localRemoteEndpoint,
		Data:   peerData,
	})
	if err != nil {
		return nil, fmt.Errorf("could not marshal response: %w", err)
	}

	return append([]byte{0x0c}, data...), nil
}
