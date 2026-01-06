package netc

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLocalAddrs(t *testing.T) {
	ls, err := LocalAddrs()
	require.NoError(t, err)

	for _, l := range ls {
		fmt.Println("addr:", l)
	}
}
