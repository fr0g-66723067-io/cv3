package main

import (
	"bytes"
	"testing"
)

func TestTerminalWriterEscapesControls(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"ansi", "\x1b[31mred\x1b[0m", `\x1b[31mred\x1b[0m`},
		{"osc8 hyperlink", "\x1b]8;;https://evil.test\x07click", `\x1b]8;;https://evil.test\x07click`},
		{"bel", "a\x07b", `a\x07b`},
		{"del", "a\x7fb", `a\x7fb`},
		{"c1", "a\u009bb", `a\x9bb`},
		{"newline and tab", "a\nb\tc", "a\nb\tc"},
		{"utf8", "café — 日本", "café — 日本"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := newTerminalWriter(&buf)
			if _, err := w.Write([]byte(tc.in)); err != nil {
				t.Fatalf("write: %v", err)
			}
			if got := buf.String(); got != tc.want {
				t.Fatalf("output = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestTerminalWriterHandlesSplitRune(t *testing.T) {
	var buf bytes.Buffer
	w := newTerminalWriter(&buf)
	if _, err := w.Write([]byte{0xc3}); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if _, err := w.Write([]byte{0xa9}); err != nil {
		t.Fatalf("second write: %v", err)
	}
	if got := buf.String(); got != "é" {
		t.Fatalf("output = %q, want é", got)
	}
}
