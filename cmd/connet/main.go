package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/mr-tron/base58"
	"github.com/quic-go/quic-go"
)

func main() {
	if err := run(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "error while running: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	conn, err := quic.DialAddr(ctx, "127.0.0.1:8443", &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-connet"},
	}, &quic.Config{})
	if err != nil {
		return err
	}
	defer conn.CloseWithError(100, "all good")

	stream, err := conn.OpenStream()
	if err != nil {
		return err
	}
	defer stream.Close()

	outBuff := binary.BigEndian.AppendUint32(nil, 32)
	if n, err := stream.Write(outBuff); err != nil {
		serr := fmt.Sprintf("could not write: %v", err)
		fmt.Fprintf(os.Stderr, "%s\n", serr)
		conn.CloseWithError(203, serr)
		return err
	} else if n < len(outBuff) {
		// TODO short write
		fmt.Fprintf(os.Stderr, "short write\n")
		conn.CloseWithError(204, "short write")
		return fmt.Errorf("short write: %d", n)
	}

	buff := make([]byte, 4)
	if n, err := stream.Read(buff); err != nil {
		serr := fmt.Sprintf("could not read: %v", err)
		fmt.Fprintf(os.Stderr, "%s\n", serr)
		conn.CloseWithError(201, serr)
		return err
	} else if n < len(buff) {
		// TODO short read
		fmt.Fprintf(os.Stderr, "short read\n")
		conn.CloseWithError(202, "short read")
		return fmt.Errorf("short read: %d", n)
	}

	fmt.Printf("Sent: %s, Recv: %s", base58.Encode(outBuff), base58.Encode(buff))
	return nil
}
