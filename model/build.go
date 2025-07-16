package model

import "runtime/debug"

// Injected by ldflags
var Version string

func BuildVersion() string {
	if Version != "" {
		return Version
	}

	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range bi.Settings {
			if setting.Key == "vcs.revision" {
				return setting.Value
			}
		}
	}

	return "/+unknown+/"
}
