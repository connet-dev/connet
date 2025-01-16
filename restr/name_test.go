package restr

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestName(t *testing.T) {
	tcs := []struct {
		name   string
		exp    string
		accept bool
	}{
		{
			name:   "exact",
			exp:    `^exact$`,
			accept: true,
		},
		{
			name:   "exact-no",
			exp:    `^exact$`,
			accept: false,
		},
		{
			name:   "oneof",
			exp:    `oneof|twoof`,
			accept: true,
		},
		{
			name:   "three",
			exp:    `oneof|twoof`,
			accept: false,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			restr, err := ParseName(tc.exp)
			require.NoError(t, err)
			require.Equal(t, tc.accept, restr.IsAllowed(tc.name))
		})
	}
}
