package iterc

import (
	"iter"
	"slices"
)

func Map[P any, R any](it iter.Seq[P], f func(P) R) iter.Seq[R] {
	return func(yield func(R) bool) {
		for p := range it {
			if !yield(f(p)) {
				return
			}
		}
	}
}

func MapSlice[S ~[]P, P any, R any](s S, f func(P) R) []R {
	return slices.Collect(Map(slices.Values(s), f))
}

func Filter[P any](it iter.Seq[P], f func(P) bool) iter.Seq[P] {
	return func(yield func(P) bool) {
		for p := range it {
			if f(p) {
				if !yield(p) {
					return
				}
			}
		}
	}
}

func FilterSlice[S ~[]P, P any](s S, f func(P) bool) S {
	return slices.Collect(Filter(slices.Values(s), f))
}

func Flatten[S ~[]P, P any](it iter.Seq[S]) iter.Seq[P] {
	return func(yield func(P) bool) {
		for s := range it {
			for _, p := range s {
				if !yield(p) {
					return
				}
			}
		}
	}
}

func FlattenSlice[SP ~[]S, S ~[]P, P any](sp SP) S {
	return slices.Collect(Flatten(slices.Values(sp)))
}
