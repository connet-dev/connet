package websocketc

import (
	"fmt"
	"net"

	"github.com/gorilla/websocket"
	"golang.org/x/sync/errgroup"
)

func Join(nc net.Conn, wc *websocket.Conn) error {
	var g errgroup.Group

	g.Go(func() error {
		defer nc.Close()
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
		//nolint:errcheck
		defer wc.Close()
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
