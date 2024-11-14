package certc

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"

	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"golang.org/x/sync/errgroup"
)

func TestChain(t *testing.T) {
	root, err := NewRoot()
	if err != nil {
		t.Fatal(err)
	}

	inter, err := root.NewIntermediate(CertOpts{
		Domains: []string{"zzz"},
	})
	if err != nil {
		t.Fatal(err)
	}
	caPool, err := inter.CertPool()
	if err != nil {
		t.Fatal(err)
	}

	server, err := inter.NewServer(CertOpts{
		Domains: []string{"zzz"},
	})
	if err != nil {
		t.Fatal(err)
	}
	serverCert, err := server.TLSCert()
	if err != nil {
		t.Fatal(err)
	}

	client, err := inter.NewClient(CertOpts{
		Domains: []string{"zzz"},
	})
	if err != nil {
		t.Fatal(err)
	}
	clientCert, err := client.TLSCert()
	if err != nil {
		t.Fatal(err)
	}

	g, ctx := errgroup.WithContext(context.Background())
	g.Go(func() error {
		udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 12345})
		if err != nil {
			return kleverr.Ret(err)
		}

		l, err := quic.Listen(udpConn, &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			ClientCAs:    caPool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			NextProtos:   []string{"test"},
		}, &quic.Config{})
		if err != nil {
			return kleverr.Ret(err)
		}

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

	g.Go(func() error {
		c, err := quic.DialAddr(ctx, "127.0.0.1:12345", &tls.Config{
			Certificates: []tls.Certificate{clientCert},
			RootCAs:      caPool,
			ServerName:   clientCert.Leaf.DNSNames[0],
			NextProtos:   []string{"test"},
		}, &quic.Config{})
		if err != nil {
			return kleverr.Ret(err)
		}
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
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := root.Cert()
	if err != nil {
		t.Fatal(err)
	}

	inter, err := root.NewIntermediate(CertOpts{
		Domains: []string{"zzz"},
	})
	if err != nil {
		t.Fatal(err)
	}
	caPool, err := inter.CertPool()
	if err != nil {
		t.Fatal(err)
	}
	caPool.AddCert(rootCert)

	server, err := root.NewServer(CertOpts{
		Domains: []string{"zzz"},
	})
	if err != nil {
		t.Fatal(err)
	}
	serverCert, err := server.TLSCert()
	if err != nil {
		t.Fatal(err)
	}

	client, err := inter.NewClient(CertOpts{
		Domains: []string{"zzz"},
	})
	if err != nil {
		t.Fatal(err)
	}
	clientCert, err := client.TLSCert()
	if err != nil {
		t.Fatal(err)
	}

	g, ctx := errgroup.WithContext(context.Background())
	g.Go(func() error {
		udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 12346})
		if err != nil {
			return kleverr.Ret(err)
		}

		l, err := quic.Listen(udpConn, &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			ClientCAs:    caPool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			NextProtos:   []string{"test"},
		}, &quic.Config{})
		if err != nil {
			return kleverr.Ret(err)
		}

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

	g.Go(func() error {
		c, err := quic.DialAddr(ctx, "127.0.0.1:12346", &tls.Config{
			Certificates: []tls.Certificate{clientCert},
			RootCAs:      caPool,
			ServerName:   clientCert.Leaf.DNSNames[0],
			NextProtos:   []string{"test"},
		}, &quic.Config{})
		if err != nil {
			return kleverr.Ret(err)
		}
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
