package certc

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func TestChain(t *testing.T) {
	root, err := NewRoot()
	require.NoError(t, err)

	caPool, err := root.CertPool()
	require.NoError(t, err)

	server, err := root.NewServer(CertOpts{
		Domains: []string{"zzz"},
	})
	require.NoError(t, err)
	serverCert, err := server.TLSCert()
	require.NoError(t, err)

	client, err := root.NewClient()
	require.NoError(t, err)
	clientCert, err := client.TLSCert()
	require.NoError(t, err)

	testConnectivity(t, serverCert, caPool, clientCert, caPool)
	testConnectivityDyn(t, serverCert, caPool, clientCert, caPool)
}

func TestChainRoot(t *testing.T) {
	root, err := NewRoot()
	require.NoError(t, err)
	rootCert, err := root.Cert()
	require.NoError(t, err)

	caPool, err := root.CertPool()
	require.NoError(t, err)
	caPool.AddCert(rootCert)

	server, err := root.NewServer(CertOpts{
		Domains: []string{"zzz"},
	})
	require.NoError(t, err)
	serverCert, err := server.TLSCert()
	require.NoError(t, err)

	client, err := root.NewClient()
	require.NoError(t, err)
	clientCert, err := client.TLSCert()
	require.NoError(t, err)

	testConnectivity(t, serverCert, caPool, clientCert, caPool)
	testConnectivityDyn(t, serverCert, caPool, clientCert, caPool)
}

func TestExchange(t *testing.T) {
	serverRoot, err := NewRoot()
	require.NoError(t, err)
	serverCA, err := serverRoot.CertPool()
	require.NoError(t, err)

	serverCert, err := serverRoot.NewServer(CertOpts{
		Domains: []string{"zzz"},
	})
	require.NoError(t, err)
	serverTLS, err := serverCert.TLSCert()
	require.NoError(t, err)

	clientRoot, err := NewRoot()
	require.NoError(t, err)
	clientCA, err := clientRoot.CertPool()
	require.NoError(t, err)

	clientCert, err := clientRoot.NewClient()
	require.NoError(t, err)
	clientTLS, err := clientCert.TLSCert()
	require.NoError(t, err)

	testConnectivity(t, serverTLS, clientCA, clientTLS, serverCA)
	testConnectivityDyn(t, serverTLS, clientCA, clientTLS, serverCA)
}

func TestMulti(t *testing.T) {
	root, err := NewRoot()
	require.NoError(t, err)

	serverCert1, err := root.NewServer(CertOpts{
		Domains: []string{"zzz1"},
	})
	require.NoError(t, err)
	serverTLS1, err := serverCert1.TLSCert()
	require.NoError(t, err)
	serverCA1, err := serverCert1.CertPool()
	require.NoError(t, err)

	clientCert1, err := root.NewClient()
	require.NoError(t, err)
	clientTLS1, err := clientCert1.TLSCert()
	require.NoError(t, err)

	serverCert2, err := root.NewServer(CertOpts{
		Domains: []string{"zzz2"},
	})
	require.NoError(t, err)
	serverTLS2, err := serverCert2.TLSCert()
	require.NoError(t, err)
	serverCA2, err := serverCert2.CertPool()
	require.NoError(t, err)

	clientCert2, err := root.NewClient()
	require.NoError(t, err)
	clientTLS2, err := clientCert2.TLSCert()
	require.NoError(t, err)

	clientCA := x509.NewCertPool()
	clientXCert1, err := clientCert1.Cert()
	require.NoError(t, err)
	clientCA.AddCert(clientXCert1)
	clientXCert2, err := clientCert2.Cert()
	require.NoError(t, err)
	clientCA.AddCert(clientXCert2)

	serverConf := &tls.Config{
		Certificates: []tls.Certificate{serverTLS1, serverTLS2},
		ClientCAs:    clientCA,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		NextProtos:   []string{"test"},
	}

	clientConf1 := &tls.Config{
		Certificates: []tls.Certificate{clientTLS1},
		RootCAs:      serverCA1,
		ServerName:   "zzz1",
		NextProtos:   []string{"test"},
	}

	testConnectivityTLS(t, serverConf, clientConf1)

	clientConf2 := &tls.Config{
		Certificates: []tls.Certificate{clientTLS2},
		RootCAs:      serverCA2,
		ServerName:   "zzz2",
		NextProtos:   []string{"test"},
	}

	testConnectivityTLS(t, serverConf, clientConf2)
}

func testConnectivity(t *testing.T, serverCert tls.Certificate, clientCA *x509.CertPool, clientCert tls.Certificate, rootCA *x509.CertPool) {
	serverConf := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    clientCA,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		NextProtos:   []string{"test"},
	}

	clientConf := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      rootCA,
		ServerName:   serverCert.Leaf.DNSNames[0],
		NextProtos:   []string{"test"},
	}

	testConnectivityTLS(t, serverConf, clientConf)
}

func testConnectivityDyn(t *testing.T, serverCert tls.Certificate, clientCA *x509.CertPool, clientCert tls.Certificate, rootCA *x509.CertPool) {
	serverConf := &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		NextProtos: []string{"test"},
	}
	serverConf.GetConfigForClient = func(_ *tls.ClientHelloInfo) (*tls.Config, error) {
		conf := serverConf.Clone()
		conf.Certificates = []tls.Certificate{serverCert}
		conf.ClientCAs = clientCA
		return conf, nil
	}

	clientConf := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      rootCA,
		ServerName:   serverCert.Leaf.DNSNames[0],
		NextProtos:   []string{"test"},
	}

	testConnectivityTLS(t, serverConf, clientConf)
}

//nolint:errcheck
func testConnectivityTLS(t *testing.T, serverConf *tls.Config, clientConf *tls.Config) {
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 12345})
	require.NoError(t, err)
	defer udpConn.Close()

	l, err := quic.Listen(udpConn, serverConf, &quic.Config{})
	require.NoError(t, err)
	defer l.Close()

	g, ctx := errgroup.WithContext(context.Background())
	g.Go(func() error {
		c, err := l.Accept(ctx)
		if err != nil {
			return fmt.Errorf("server accept conn: %w", err)
		}

		peerCerts := c.ConnectionState().TLS.PeerCertificates
		if len(peerCerts) != 1 {
			return fmt.Errorf("expected 1 client certificate, but found: %d", len(peerCerts))
		}
		if !bytes.Equal(peerCerts[0].Raw, clientConf.Certificates[0].Leaf.Raw) {
			return fmt.Errorf("expected matching certs")
		}

		s, err := c.AcceptStream(ctx)
		if err != nil {
			return fmt.Errorf("server accept stream: %w", err)
		}
		defer s.Close()

		buf := make([]byte, 1)
		if _, err := io.ReadFull(s, buf); err != nil {
			return fmt.Errorf("server read: %w", err)
		}
		if _, err := s.Write(buf); err != nil {
			return fmt.Errorf("server write: %w", err)
		}
		return nil
	})

	c, err := quic.DialAddr(ctx, "127.0.0.1:12345", clientConf, &quic.Config{})
	require.NoError(t, err)
	defer c.CloseWithError(0, "done")

	g.Go(func() error {
		s, err := c.OpenStreamSync(context.Background())
		if err != nil {
			return fmt.Errorf("client stream: %w", err)
		}
		defer s.Close()

		buf := make([]byte, 1)
		buf[0] = 33
		if _, err := s.Write(buf); err != nil {
			return fmt.Errorf("client write: %w", err)
		}
		buf[0] = 0
		if _, err := io.ReadFull(s, buf); err != nil {
			return fmt.Errorf("client read: %w", err)
		}
		return nil
	})

	err = g.Wait()
	require.NoError(t, err)
}
