package netc

import (
	"context"
	"io"
	"net"

	"golang.org/x/sync/errgroup"
)

func Join(ctx context.Context, l io.ReadWriteCloser, r io.ReadWriteCloser) error {
	g, _ := errgroup.WithContext(ctx)
	g.Go(func() error {
		defer l.Close()
		_, err := io.Copy(l, r)
		return err
	})
	g.Go(func() error {
		defer r.Close()
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
			defer acceptConn.Close()

			dialConn, err := j.Dial(ctx)
			if err != nil {
				return
			}
			defer dialConn.Close()

			j.Join(ctx, acceptConn, dialConn)
		}()
	}
}
