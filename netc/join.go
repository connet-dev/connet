package netc

import (
	"context"
	"io"
	"os"

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
