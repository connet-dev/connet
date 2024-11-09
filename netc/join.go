package netc

import (
	"context"
	"io"

	"golang.org/x/sync/errgroup"
)

func Join(ctx context.Context, l io.ReadWriteCloser, r io.ReadWriteCloser) error {
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
