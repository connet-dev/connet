package notify

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNV(t *testing.T) {
	n := NewEmpty[int]()

	go func() {
		for i := 0; i <= 1000; i++ {
			n.Set(i)
		}
	}()

	version := uint64(0)
	observed := 0
	for {
		v, next, err := n.Get(context.Background(), version)
		require.NoError(t, err)
		version = next
		observed++
		if v == 1000 {
			break
		}
	}
	fmt.Println("observed", observed)
}
