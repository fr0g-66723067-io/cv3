package main

import "runtime/debug"

// buildStamp reports the version and commit printed by `cv3 version`.
//
// The Makefile supplies both with -ldflags, and those always win. Without them
// — `go install …@vX.Y.Z`, or a plain `go build` — the values Go embeds in the
// binary are used instead, so a tag-installed CLI names its tag rather than
// reporting "dev".
func buildStamp() (string, string) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return version, commit
	}
	return stampFrom(version, commit, info)
}

// stampFrom is buildStamp's decision table, split out so it can be tested with
// synthetic build info: -ldflags beats module metadata, module metadata beats
// the dev/none defaults.
func stampFrom(ldVersion, ldCommit string, info *debug.BuildInfo) (string, string) {
	v, c := ldVersion, ldCommit
	if info == nil {
		return v, c
	}
	if v == "dev" {
		if mv := info.Main.Version; mv != "" && mv != "(devel)" {
			v = mv
		}
	}
	for _, s := range info.Settings {
		if s.Key != "vcs.revision" || len(s.Value) < 7 {
			continue
		}
		if c == "none" {
			c = s.Value[:7]
		}
		if v == "dev" {
			for _, m := range info.Settings {
				if m.Key == "vcs.modified" && m.Value == "true" {
					v = "dev-dirty"
					break
				}
			}
		}
		break
	}
	return v, c
}
