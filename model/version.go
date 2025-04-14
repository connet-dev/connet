package model

import "runtime/debug"

func GetBuildVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range bi.Settings {
			if setting.Key == "vcs.revision" {
				return setting.Value
			}
		}
	}

	return "/+unknown+/"
}
