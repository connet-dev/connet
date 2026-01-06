package iterc

import "fmt"

func MapVarStrings[P fmt.Stringer](s ...P) []string {
	return MapSliceStrings(s)
}
