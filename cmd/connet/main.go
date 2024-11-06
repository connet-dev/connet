package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"go.connet.dev/lib/netc"
	"go.connet.dev/lib/protocol"
)

var auth = flag.String("auth", "", "authentication token")
var listenName = flag.String("listen-name", "", "name to listen on")
var listenTarget = flag.String("listen-target", "", "forward incoming conns to")
var connectName = flag.String("connect-name", "", "name to connect to")
var connectSource = flag.String("connect-source", "", "listen for incoming conns")

func main() {
	flag.Parse()

	if *listenName != "" {
		if err := listen(context.Background(), *listenName, *listenTarget); err != nil {
			fmt.Fprintf(os.Stderr, "error while running: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *connectName != "" {
		if err := connect(context.Background(), *connectName, *connectSource); err != nil {
			fmt.Fprintf(os.Stderr, "error while running: %v\n", err)
			os.Exit(1)
		}
		return
	}

	flag.PrintDefaults()
}

func open(ctx context.Context) (quic.Connection, error) {
	conn, err := quic.DialAddr(ctx, "127.0.0.1:8443", &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-connet"},
	}, &quic.Config{
		KeepAlivePeriod: 25 * time.Second,
	})
	if err != nil {
		return nil, kleverr.Ret(err)
	}

	authStream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, kleverr.Ret(err)
	}
	defer authStream.Close()

	if err := protocol.RequestAuth.Write(authStream, *auth); err != nil {
		return nil, kleverr.Ret(err)
	}
	authResp, err := protocol.ReadResponse(authStream)
	if err != nil {
		return nil, kleverr.Ret(err)
	}
	fmt.Println("authenticated:", authResp)

	return conn, nil
}

func listen(ctx context.Context, name string, target string) error {
	conn, err := open(ctx)
	if err != nil {
		return err
	}

	cmdStream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return kleverr.Ret(err)
	}

	if err := protocol.RequestListen.Write(cmdStream, name); err != nil {
		return kleverr.Ret(err)
	}
	result, err := protocol.ReadResponse(cmdStream)
	if err != nil {
		return kleverr.Ret(err)
	}
	fmt.Printf("register %s: %s\n", name, result)

	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return kleverr.Ret(err)
		}

		conn, err := net.Dial("tcp", target)
		if err != nil {
			return kleverr.Ret(err)
		}

		go func() {
			if err := netc.Join(ctx, stream, conn); err != nil {
				fmt.Fprintf(os.Stderr, "%s\n", err.Error())
			}
		}()
	}
}

func connect(ctx context.Context, name string, target string) error {
	conn, err := open(ctx)
	if err != nil {
		return kleverr.Ret(err)
	}

	l, err := net.Listen("tcp", target)
	if err != nil {
		return kleverr.Ret(err)
	}

	for {
		srcConn, err := l.Accept()
		if err != nil {
			return kleverr.Ret(err)
		}
		fmt.Println("received conn from:", srcConn.RemoteAddr())

		stream, err := conn.OpenStreamSync(ctx)
		if err != nil {
			return kleverr.Ret(err)
		}
		if err := protocol.RequestConnect.Write(stream, name); err != nil {
			return kleverr.Ret(err)
		}
		result, err := protocol.ReadResponse(stream)
		if err != nil {
			return kleverr.Ret(err)
		}
		fmt.Println("connected to server:", result)

		go func() {
			if err := netc.Join(ctx, stream, srcConn); err != nil {
				fmt.Fprintf(os.Stderr, "%s\n", err.Error())
			}
		}()
	}
}
