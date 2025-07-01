package netc

import (
	"context"
	"io"
	"net"

	"github.com/connet-dev/connet/slogc"
	"golang.org/x/sync/errgroup"
)

func Join(l io.ReadWriteCloser, r io.ReadWriteCloser) error {
	var g errgroup.Group
	g.Go(func() error {
		defer func() {
			if err := l.Close(); err != nil {
				slogc.FineDefault("error closing lconn", "err", err)
			}
		}()
		_, err := io.Copy(l, r)
		return err
	})
	g.Go(func() error {
		defer func() {
			if err := r.Close(); err != nil {
				slogc.FineDefault("error closing rconn", "err", err)
			}
		}()
		_, err := io.Copy(r, l)
		return err
	})
	return g.Wait()
}

type Joiner struct {
	Accept func(context.Context) (net.Conn, error)
	Dial   func(context.Context) (net.Conn, error)
	Join   func(ctx context.Context, acceptConn net.Conn, dialConn net.Conn)
}

func (j *Joiner) Run(ctx context.Context) error {
	for {
		acceptConn, err := j.Accept(ctx)
		if err != nil {
			return err
		}

		go func() {
			defer func() {
				if err := acceptConn.Close(); err != nil {
					slogc.FineDefault("error closing accepted conn", "err", err)
				}
			}()

			dialConn, err := j.Dial(ctx)
			if err != nil {
				return
			}
			defer func() {
				if err := dialConn.Close(); err != nil {
					slogc.FineDefault("error closing dial conn", "err", err)
				}
			}()

			j.Join(ctx, acceptConn, dialConn)
		}()
	}
}
