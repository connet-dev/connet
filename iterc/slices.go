package iterc

import "slices"

func MapSlice[S ~[]P, P any, R any](s S, f func(P) R) []R {
	return slices.Collect(Map(slices.Values(s), f))
}

func FilterSlice[S ~[]P, P any](s S, f func(P) bool) S {
	return slices.Collect(Filter(slices.Values(s), f))
}

func FlattenSlice[SP ~[]S, S ~[]P, P any](sp SP) S {
	return slices.Collect(Flatten(slices.Values(sp)))
}
