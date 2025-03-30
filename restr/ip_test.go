package restr

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIP(t *testing.T) {
	tcs := []struct {
		name   string
		allow  []string
		deny   []string
		check  string
		accept bool
	}{
		{
			name:   "empty",
			check:  "10.100.2.100",
			accept: true,
		},
		{
			name:   "allow match",
			allow:  []string{"10.100.2.0/24"},
			check:  "10.100.2.100",
			accept: true,
		},
		{
			name:   "allow nomatch",
			allow:  []string{"10.100.2.0/24"},
			check:  "10.101.2.100",
			accept: false,
		},
		{
			name:   "deny match",
			deny:   []string{"10.100.2.0/24"},
			check:  "10.100.2.100",
			accept: false,
		},
		{
			name:   "deny empty allow",
			deny:   []string{"10.100.2.0/24"},
			check:  "10.101.2.100",
			accept: true,
		},
		{
			name:   "deny with allow",
			allow:  []string{"10.100.2.0/24"},
			deny:   []string{"10.100.2.0/24"},
			check:  "10.100.2.100",
			accept: false,
		},
		{
			name:   "allow explicit",
			allow:  []string{"10.101.2.0/24"},
			deny:   []string{"10.100.2.0/24"},
			check:  "10.102.2.100",
			accept: false,
		},
		{
			name:   "allow exact",
			allow:  []string{"10.101.2.0/24"},
			deny:   []string{"10.100.2.0/24"},
			check:  "10.101.2.100",
			accept: true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			restr, err := ParseIP(tc.allow, tc.deny)
			require.NoError(t, err)
			require.Equal(t, tc.accept, restr.IsAllowed(netip.MustParseAddr(tc.check)))
		})
	}
}
