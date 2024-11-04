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
	"math/big"
	"net"
	"os"
	"time"

	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
)

func main() {
	if err := run(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "error while running: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	// pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	// san := pkix.Extension{}
	// san.Id = objectIdentifier
	// san.Critical = false
	// san.Value = []byte(fmt.Sprintf("CN=%s", cfg.Name))

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
		IsCA:         true,
	}
	certData, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		return kleverr.Ret(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certData,
	})

	b, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return kleverr.Ret(err)
	}
	certKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: b,
	})

	cert, err := tls.X509KeyPair(certPEM, certKeyPEM)
	if err != nil {
		return kleverr.Ret(err)
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
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			serr := fmt.Sprintf("could not accept: %v", err)
			fmt.Fprintf(os.Stderr, "%s\n", serr)
			conn.CloseWithError(200, serr)
			continue
		}

		buff := make([]byte, 4)
		if n, err := stream.Read(buff); err != nil {
			serr := fmt.Sprintf("could not read: %v", err)
			fmt.Fprintf(os.Stderr, "%s\n", serr)
			conn.CloseWithError(201, serr)
			continue
		} else if n < len(buff) {
			// TODO short read
			fmt.Fprintf(os.Stderr, "short read\n")
			conn.CloseWithError(202, "short read")
			continue
		}

		if n, err := stream.Write(buff); err != nil {
			serr := fmt.Sprintf("could not write: %v", err)
			fmt.Fprintf(os.Stderr, "%s\n", serr)
			conn.CloseWithError(203, serr)
			continue
		} else if n < len(buff) {
			// TODO short write
			fmt.Fprintf(os.Stderr, "short write\n")
			conn.CloseWithError(204, "short write")
			continue
		}

		time.Sleep(time.Second)
		conn.CloseWithError(100, "closing conn")
	}

	return nil
}
