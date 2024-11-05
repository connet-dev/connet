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
	"sync"
	"time"

	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"go.connet.dev/lib/netc"
	"go.connet.dev/lib/protocol"
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
	authStream, err := conn.AcceptStream(ctx)
	if err != nil {
		return kleverr.Ret(err)
	}
	defer authStream.Close()

	req, auth, err := protocol.ReadRequest(authStream)
	switch {
	case err != nil:
		return kleverr.Ret(err)
	case req != protocol.RequestAuth:
		return protocol.ResponseAuthExpected.Write(authStream, fmt.Sprintf("expected auth, but got %v", req))
	case auth != "abc":
		return protocol.ResponseAuthInvalid.Write(authStream, "invalid token")
	default:
		if err := protocol.ResponseOk.Write(authStream, "ok"); err != nil {
			return kleverr.Ret(err)
		}
	}

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
	req, addr, err := protocol.ReadRequest(stream)
	if err != nil {
		return err
	}
	fmt.Printf("request %v: %s\n", req, addr)

	switch req {
	case protocol.RequestListen:
		addrsMu.Lock()
		addrs[addr] = conn
		addrsMu.Unlock()

		if err := protocol.ResponseOk.Write(stream, "ok"); err != nil {
			return err
		}
		return stream.Close()
	case protocol.RequestConnect:
		addrsMu.RLock()
		otherConn, ok := addrs[addr]
		addrsMu.RUnlock()

		if !ok {
			if err := protocol.ResponseListenNotFound.Write(stream, fmt.Sprintf("%s is not known to this server", addr)); err != nil {
				return err
			}
			return stream.Close()
		}

		otherStream, err := otherConn.OpenStreamSync(ctx)
		if err != nil {
			if err := protocol.ResponseListenNotDialed.Write(stream, fmt.Sprintf("%s dial failed: %v", addr, err)); err != nil {
				return err
			}
			return stream.Close()
		}

		if err := protocol.ResponseOk.Write(stream, "ok"); err != nil {
			return err
		}
		return netc.Join(ctx, stream, otherStream)
	default:
		if err := protocol.ResponseRequestInvalid.Write(stream, fmt.Sprintf("%d is not valid request", req)); err != nil {
			return err
		}
		return stream.Close()
	}
}
