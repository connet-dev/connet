package certc

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"

	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func TestChain(t *testing.T) {
	root, err := NewRoot()
	require.NoError(t, err)

	inter, err := root.NewIntermediate(CertOpts{
		Domains: []string{"zzz"},
	})
	require.NoError(t, err)
	caPool, err := inter.CertPool()
	require.NoError(t, err)

	server, err := inter.NewServer(CertOpts{
		Domains: []string{"zzz"},
	})
	require.NoError(t, err)
	serverCert, err := server.TLSCert()
	require.NoError(t, err)

	client, err := inter.NewClient(CertOpts{
		Domains: []string{"zzz"},
	})
	require.NoError(t, err)
	clientCert, err := client.TLSCert()
	require.NoError(t, err)

	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 12345})
	require.NoError(t, err)
	defer udpConn.Close()

	l, err := quic.Listen(udpConn, &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		NextProtos:   []string{"test"},
	}, &quic.Config{})
	require.NoError(t, err)
	defer l.Close()

	g, ctx := errgroup.WithContext(context.Background())
	g.Go(func() error {

		c, err := l.Accept(ctx)
		if err != nil {
			return kleverr.Ret(err)
		}
		s, err := c.AcceptStream(ctx)
		if err != nil {
			return kleverr.Ret(err)
		}
		defer s.Close()

		buf := make([]byte, 1)
		if _, err := io.ReadFull(s, buf); err != nil {
			return kleverr.Ret(err)
		}
		if _, err := s.Write(buf); err != nil {
			return kleverr.Ret(err)
		}
		return nil
	})

	c, err := quic.DialAddr(ctx, "127.0.0.1:12345", &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
		ServerName:   clientCert.Leaf.DNSNames[0],
		NextProtos:   []string{"test"},
	}, &quic.Config{})
	require.NoError(t, err)
	defer c.CloseWithError(0, "done")

	g.Go(func() error {
		s, err := c.OpenStreamSync(context.Background())
		if err != nil {
			return kleverr.Ret(err)
		}
		defer s.Close()

		buf := make([]byte, 1)
		buf[0] = 33
		if _, err := s.Write(buf); err != nil {
			return kleverr.Ret(err)
		}
		buf[0] = 0
		if _, err := io.ReadFull(s, buf); err != nil {
			return kleverr.Ret(err)
		}
		return nil
	})

	if err := g.Wait(); err != nil {
		if kerr := kleverr.Get(err); kerr != nil {
			t.Fatal(kerr.Print())
		}
		t.Fatal(err)
	}
}

func TestChainRoot(t *testing.T) {
	root, err := NewRoot()
	require.NoError(t, err)
	rootCert, err := root.Cert()
	require.NoError(t, err)

	inter, err := root.NewIntermediate(CertOpts{
		Domains: []string{"zzz"},
	})
	require.NoError(t, err)
	caPool, err := inter.CertPool()
	require.NoError(t, err)
	caPool.AddCert(rootCert)

	server, err := root.NewServer(CertOpts{
		Domains: []string{"zzz"},
	})
	require.NoError(t, err)
	serverCert, err := server.TLSCert()
	require.NoError(t, err)

	client, err := inter.NewClient(CertOpts{
		Domains: []string{"zzz"},
	})
	require.NoError(t, err)
	clientCert, err := client.TLSCert()
	require.NoError(t, err)

	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 12345})
	require.NoError(t, err)
	defer udpConn.Close()

	l, err := quic.Listen(udpConn, &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		NextProtos:   []string{"test"},
	}, &quic.Config{})
	require.NoError(t, err)
	defer l.Close()

	g, ctx := errgroup.WithContext(context.Background())
	g.Go(func() error {
		c, err := l.Accept(ctx)
		if err != nil {
			return kleverr.Ret(err)
		}
		s, err := c.AcceptStream(ctx)
		if err != nil {
			return kleverr.Ret(err)
		}
		defer s.Close()

		buf := make([]byte, 1)
		if _, err := io.ReadFull(s, buf); err != nil {
			return kleverr.Ret(err)
		}
		if _, err := s.Write(buf); err != nil {
			return kleverr.Ret(err)
		}
		return nil
	})

	c, err := quic.DialAddr(ctx, "127.0.0.1:12345", &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
		ServerName:   clientCert.Leaf.DNSNames[0],
		NextProtos:   []string{"test"},
	}, &quic.Config{})
	require.NoError(t, err)
	defer c.CloseWithError(0, "done")

	g.Go(func() error {
		s, err := c.OpenStreamSync(context.Background())
		if err != nil {
			return kleverr.Ret(err)
		}
		defer s.Close()

		buf := make([]byte, 1)
		buf[0] = 33
		if _, err := s.Write(buf); err != nil {
			return kleverr.Ret(err)
		}
		buf[0] = 0
		if _, err := io.ReadFull(s, buf); err != nil {
			return kleverr.Ret(err)
		}
		return nil
	})

	if err := g.Wait(); err != nil {
		if kerr := kleverr.Get(err); kerr != nil {
			t.Fatal(kerr.Print())
		}
		t.Fatal(err)
	}
}
