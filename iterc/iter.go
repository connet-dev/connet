package iterc

import (
	"iter"
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
