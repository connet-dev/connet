package iterc

import (
	"iter"
	"slices"
)

func Map[P any, R any](it iter.Seq[P], f func(P) R) iter.Seq[R] {
	return func(yield func(R) bool) {
		for p := range it {
			yield(f(p))
		}
	}
}

func MapSlice[SP ~[]P, P any, R any](s SP, f func(P) R) []R {
	return slices.Collect(Map(slices.Values(s), f))
}
