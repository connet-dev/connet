package iterc

import (
	"fmt"
	"slices"
)

// MapSlice returns a slice that has each of it elements mapped by applying f on the elements
func MapSlice[S ~[]P, P any, R any](s S, f func(P) R) []R {
	return slices.Collect(Map(slices.Values(s), f))
}

// MapSliceStrings is like map, but uses [fmt.Stringer] to map to slice of strings
func MapSliceStrings[S ~[]P, P fmt.Stringer](s S) []string {
	return slices.Collect(Map(slices.Values(s), P.String))
}

// FilterSlice returns a copy of the slice which contains only elements for which f returns true
func FilterSlice[S ~[]P, P any](s S, f func(P) bool) S {
	return slices.Collect(Filter(slices.Values(s), f))
}

func FlattenSlice[SP ~[]S, S ~[]P, P any](sp SP) S {
	return slices.Collect(Flatten(slices.Values(sp)))
}
