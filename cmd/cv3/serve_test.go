package main

import (
	"strings"
	"testing"
)

func TestIsLoopbackHost(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1":  true,
		"::1":        true,
		"localhost":  true,
		"LOCALHOST":  true,
		"0.0.0.0":    false,
		"::":         false,
		"192.0.2.10": false,
		"":           false,
	}
	for host, want := range cases {
		if got := isLoopbackHost(host); got != want {
			t.Errorf("isLoopbackHost(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestServeRejectsRemoteBindWithoutToken(t *testing.T) {
	t.Setenv("CV3_SERVE_TOKEN", "")
	code, _, stderr := runCLI("serve", "-addr", "0.0.0.0:0")
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, exitUsage, stderr)
	}
	if !strings.Contains(stderr, "CV3_SERVE_TOKEN") {
		t.Fatalf("stderr does not name CV3_SERVE_TOKEN: %s", stderr)
	}
}
