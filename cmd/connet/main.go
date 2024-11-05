package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/klev-dev/kleverr"
	"github.com/quic-go/quic-go"
	"go.connet.dev/lib/protocol"
	"golang.org/x/sync/errgroup"
)

var listenName = flag.String("listen-name", "", "name to listen on")
var listenTarget = flag.String("listen-target", "", "target to forward to")
var connectName = flag.String("connect-name", "", "name to connect to")
var connectTarget = flag.String("connect-target", "", "port to listen for conns")

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
		if err := connect(context.Background(), *connectName, *connectTarget); err != nil {
			fmt.Fprintf(os.Stderr, "error while running: %v\n", err)
			os.Exit(1)
		}
		return
	}

	flag.PrintDefaults()
}

func open(ctx context.Context) (quic.Connection, error) {
	return quic.DialAddr(ctx, "127.0.0.1:8443", &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-connet"},
	}, &quic.Config{})
}

func listen(ctx context.Context, name string, target string) error {
	conn, err := open(ctx)
	if err != nil {
		return kleverr.Ret(err)
	}

	cmdStream, err := conn.OpenStream()
	if err != nil {
		return kleverr.Ret(err)
	}

	if err := protocol.WriteCmd(cmdStream, 1, name); err != nil {
		return kleverr.Ret(err)
	}
	status, statusText, err := protocol.ReadCmd(cmdStream)
	switch {
	case err != nil:
		return kleverr.Ret(err)
	case status > 0:
		return kleverr.Newf("%d: %s", status, statusText)
	}

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
			if err := join(ctx, stream, conn); err != nil {
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
		if err := protocol.WriteCmd(stream, 2, name); err != nil {
			return kleverr.Ret(err)
		}
		status, statusText, err := protocol.ReadCmd(stream)
		switch {
		case err != nil:
			return kleverr.Ret(err)
		case status > 0:
			return kleverr.Newf("%d: %s", status, statusText)
		}
		fmt.Println("connected to server:", statusText)

		go func() {
			if err := join(ctx, stream, srcConn); err != nil {
				fmt.Fprintf(os.Stderr, "%s\n", err.Error())
			}
		}()
	}
}

func join(ctx context.Context, l quic.Stream, r net.Conn) error {
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
