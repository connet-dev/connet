package client

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/connet-dev/connet/model"
	"github.com/connet-dev/connet/netc"
)

type DestinationServer struct {
	dst    *Destination
	addr   string
	logger *slog.Logger
}

func NewDestinationServer(dst *Destination, fwd model.Forward, addr string, logger *slog.Logger) *DestinationServer {
	return &DestinationServer{
		dst:    dst,
		addr:   addr,
		logger: logger.With("destination", fwd, "addr", addr),
	}
}

func (d *DestinationServer) Run(ctx context.Context) error {
	for {
		conn, err := d.dst.Accept()
		if err != nil {
			return err
		}
		go d.runConn(ctx, conn)
	}
}

func (d *DestinationServer) runConn(ctx context.Context, remoteConn net.Conn) {
	defer remoteConn.Close()

	if err := d.acceptConnErr(ctx, remoteConn); err != nil {
		d.logger.Warn("destination conn error", "err", err)
	}
}

func (d *DestinationServer) acceptConnErr(ctx context.Context, remoteConn net.Conn) error {
	conn, err := net.Dial("tcp", d.addr)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	err = netc.Join(ctx, remoteConn, conn)
	d.logger.Debug("disconnected conns", "err", err)

	return nil
}
