package certc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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

	testConnectivity(t, serverCert, caPool, clientCert, caPool)
	testConnectivityDyn(t, serverCert, caPool, clientCert, caPool)
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

	clientCert, err := clientRoot.NewClient(CertOpts{
		Domains: []string{"zzz"},
	})
	require.NoError(t, err)
	clientTLS, err := clientCert.TLSCert()
	require.NoError(t, err)

	testConnectivity(t, serverTLS, clientCA, clientTLS, serverCA)
	testConnectivityDyn(t, serverTLS, clientCA, clientTLS, serverCA)
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
		ServerName:   clientCert.Leaf.DNSNames[0],
		NextProtos:   []string{"test"},
	}

	testConnectivityTLS(t, serverConf, clientConf)
}

func testConnectivityDyn(t *testing.T, serverCert tls.Certificate, clientCA *x509.CertPool, clientCert tls.Certificate, rootCA *x509.CertPool) {
	serverConf := &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		NextProtos: []string{"test"},
	}
	serverConf.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		conf := serverConf.Clone()
		conf.Certificates = []tls.Certificate{serverCert}
		conf.ClientCAs = clientCA
		return conf, nil
	}

	clientConf := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      rootCA,
		ServerName:   clientCert.Leaf.DNSNames[0],
		NextProtos:   []string{"test"},
	}

	testConnectivityTLS(t, serverConf, clientConf)
}

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

	c, err := quic.DialAddr(ctx, "127.0.0.1:12345", clientConf, &quic.Config{})
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

	err = g.Wait()
	require.NoError(t, err)
}
