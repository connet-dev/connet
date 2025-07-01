package websocketc

import (
	"fmt"
	"net"

	"github.com/connet-dev/connet/slogc"
	"github.com/gorilla/websocket"
	"golang.org/x/sync/errgroup"
)

func Join(nc net.Conn, wc *websocket.Conn) error {
	var g errgroup.Group

	g.Go(func() error {
		defer func() {
			if err := nc.Close(); err != nil {
				slogc.FineDefault("error closing source connection", "err", err)
			}
		}()
		for {
			_, data, err := wc.ReadMessage()
			if err != nil {
				return fmt.Errorf("websocked connection read: %w", err)
			}
			if _, err := nc.Write(data); err != nil {
				return fmt.Errorf("source connection write: %w", err)
			}
		}
	})

	g.Go(func() error {
		defer func() {
			if err := wc.Close(); err != nil {
				slogc.FineDefault("error closing websocket connection", "err", err)
			}
		}()
		var buf = make([]byte, 4096)
		for {
			n, err := nc.Read(buf)
			if err != nil {
				return fmt.Errorf("source connection read: %w", err)
			}
			if err := wc.WriteMessage(websocket.BinaryMessage, buf[0:n]); err != nil {
				return fmt.Errorf("websocked connection write: %w", err)
			}
		}
	})

	return g.Wait()
}
