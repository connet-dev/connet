package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"go.connet.dev/lib/protocol"
	"golang.org/x/sync/errgroup"
)

var addrs = map[string]quic.Connection{}
var addrsMu = sync.RWMutex{}

func main() {
	if err := run(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "error while running: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	cert, err := createCert()
	if err != nil {
		return err
	}

	addr, err := net.ResolveUDPAddr("udp", "0.0.0.0:8443")
	if err != nil {
		return kleverr.Ret(err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return kleverr.Ret(err)
	}

	tr := &quic.Transport{
		Conn: conn,
		// TODO review other options
	}
	l, err := tr.Listen(&tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"quic-connet"},
	}, &quic.Config{
		KeepAlivePeriod: 25 * time.Second,
	})
	if err != nil {
		return kleverr.Ret(err)
	}

	fmt.Println("Started connet-server")
	defer fmt.Println("Stopped connet-server")
	for {
		conn, err := l.Accept(ctx)
		if err != nil {
			if errors.Is(err, quic.ErrServerClosed) {
				break
			}
		}
		go func() {
			if err := handleConn(ctx, conn); err != nil {
				fmt.Fprintf(os.Stderr, "%s\n", err.Error())
				conn.CloseWithError(200, err.Error())
			} else {
				conn.CloseWithError(0, "ok")
			}
		}()
	}

	return nil
}

func handleConn(ctx context.Context, conn quic.Connection) error {
	defer func() {
		addrsMu.Lock()
		defer addrsMu.Unlock()

		for k, v := range addrs {
			if v == conn {
				delete(addrs, k)
			}
		}
	}()
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return kleverr.Newf("could not accept: %w", err)
		}
		go func() {
			if err := handleStream(ctx, conn, stream); err != nil {
				fmt.Fprintf(os.Stderr, "%s\n", err.Error())
			}
		}()
	}
}

func handleStream(ctx context.Context, conn quic.Connection, stream quic.Stream) error {
	cmd, addr, err := protocol.ReadCmd(stream)
	if err != nil {
		return err
	}
	fmt.Printf("request %d: %s\n", cmd, addr)

	switch cmd {
	case 1: // listen
		addrsMu.Lock()
		addrs[addr] = conn
		addrsMu.Unlock()

		if err := protocol.WriteCmd(stream, 0, "ok"); err != nil {
			return err
		}
		return stream.Close()
	case 2: // connect
		addrsMu.RLock()
		otherConn, ok := addrs[addr]
		addrsMu.RUnlock()

		if !ok {
			if err := protocol.WriteCmd(stream, 2, "name-not-found"); err != nil {
				return err
			}
			return stream.Close()
		}

		otherStream, err := otherConn.OpenStream()
		if err != nil {
			if err := protocol.WriteCmd(stream, 3, "name-not-connect"); err != nil {
				return err
			}
			return stream.Close()
		}

		if err := protocol.WriteCmd(stream, 0, "ok"); err != nil {
			return err
		}
		return join(ctx, stream, otherStream)
	default:
		if err := protocol.WriteCmd(stream, 1, "cmd-not-found"); err != nil {
			return err
		}
		return stream.Close()
	}
}

func join(ctx context.Context, l quic.Stream, r quic.Stream) error {
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		defer l.Close()
		_, err := io.Copy(l, r)
		return err
	})
	eg.Go(func() error {
		defer r.Close()
		_, err := io.Copy(r, l)
		return err
	})
	return eg.Wait()
}

func createCert() (tls.Certificate, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixMilli()),
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"Connet"},
		},
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		// IsCA:         true,
	}
	certData, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		return tls.Certificate{}, kleverr.Ret(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certData,
	})

	keyData, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, kleverr.Ret(err)
	}
	certKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyData,
	})

	cert, err := tls.X509KeyPair(certPEM, certKeyPEM)
	if err != nil {
		return tls.Certificate{}, kleverr.Ret(err)
	}
	return cert, nil
}
