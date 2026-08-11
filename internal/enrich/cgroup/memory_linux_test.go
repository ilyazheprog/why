//go:build linux

package cgroup

import "testing"

func TestParseUnifiedPath(t *testing.T) {
	path, err := ParseUnifiedPath("0::/user.slice/app.scope\n")
	if err != nil || path != "/user.slice/app.scope" {
		t.Fatalf("path=%q err=%v", path, err)
	}
}

func TestCorrelateRejectsDifferentCgroups(t *testing.T) {
	if got := Correlate(MemorySnapshot{Path: "/a"}, MemorySnapshot{Path: "/b"}); got != nil {
		t.Fatalf("unexpected correlation: %#v", got)
	}
}
