package main

import (
	"runtime/debug"
	"testing"
)

func TestStampFrom(t *testing.T) {
	const rev = "41410e0fff99f40013294695b48704651cc14044"
	cases := []struct {
		name        string
		ldVersion   string
		ldCommit    string
		info        *debug.BuildInfo
		wantVersion string
		wantCommit  string
	}{
		{
			name:        "ldflags win over module metadata",
			ldVersion:   "v0.1.2",
			ldCommit:    "abc1234",
			info:        &debug.BuildInfo{Main: debug.Module{Version: "v9.9.9"}, Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: rev}}},
			wantVersion: "v0.1.2",
			wantCommit:  "abc1234",
		},
		{
			name:        "go install names the tag",
			ldVersion:   "dev",
			ldCommit:    "none",
			info:        &debug.BuildInfo{Main: debug.Module{Version: "v0.1.2"}},
			wantVersion: "v0.1.2",
			wantCommit:  "none",
		},
		{
			name:        "devel build takes the commit",
			ldVersion:   "dev",
			ldCommit:    "none",
			info:        &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}, Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: rev}}},
			wantVersion: "dev",
			wantCommit:  "41410e0",
		},
		{
			name:        "empty module version stays dev",
			ldVersion:   "dev",
			ldCommit:    "none",
			info:        &debug.BuildInfo{Main: debug.Module{Version: ""}},
			wantVersion: "dev",
			wantCommit:  "none",
		},
		{
			name:        "dirty checkout is marked",
			ldVersion:   "dev",
			ldCommit:    "none",
			info:        &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}, Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: rev}, {Key: "vcs.modified", Value: "true"}}},
			wantVersion: "dev-dirty",
			wantCommit:  "41410e0",
		},
		{
			name:        "short revision is not a commit",
			ldVersion:   "dev",
			ldCommit:    "none",
			info:        &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}, Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "abc"}}},
			wantVersion: "dev",
			wantCommit:  "none",
		},
		{
			name:        "no build info",
			ldVersion:   "dev",
			ldCommit:    "none",
			info:        nil,
			wantVersion: "dev",
			wantCommit:  "none",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, c := stampFrom(tc.ldVersion, tc.ldCommit, tc.info)
			if v != tc.wantVersion || c != tc.wantCommit {
				t.Fatalf("stampFrom(%q, %q) = (%q, %q), want (%q, %q)",
					tc.ldVersion, tc.ldCommit, v, c, tc.wantVersion, tc.wantCommit)
			}
		})
	}
}
