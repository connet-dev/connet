package iterc

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFilter(t *testing.T) {
	vals := []string{"a", "b", "c"}
	require.Equal(t, []string{"a", "b"}, FilterSlice(vals, func(el string) bool { return el != "c" }))
}
