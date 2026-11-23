package main

import (
	"io"
	"unicode/utf8"
)

const hexDigits = "0123456789abcdef"

// terminalWriter escapes control runes written to a terminal-facing stream.
// CVE text comes from upstream feeds: raw ESC/BEL/C1 bytes let a crafted record
// move the cursor, spoof lines, or open OSC 8 links. Only the text renderers
// wrap their writer; JSON output is never passed through this filter because
// encoding/json leaves DEL and C1 runes unescaped and rewriting them would
// corrupt the document.
type terminalWriter struct {
	dst     io.Writer
	pending [utf8.UTFMax]byte
	n       int
}

// newTerminalWriter returns a writer that renders control runes as visible
// \xNN text and preserves newlines, tabs, and ordinary UTF-8.
func newTerminalWriter(w io.Writer) io.Writer {
	return &terminalWriter{dst: w}
}

func (t *terminalWriter) Write(p []byte) (int, error) {
	buf := p
	if t.n > 0 {
		joined := make([]byte, 0, t.n+len(p))
		joined = append(joined, t.pending[:t.n]...)
		joined = append(joined, p...)
		buf = joined
		t.n = 0
	}
	out := make([]byte, 0, len(buf))
	for len(buf) > 0 {
		r, size := utf8.DecodeRune(buf)
		if r == utf8.RuneError && size == 1 {
			if !utf8.FullRune(buf) {
				// A multi-byte rune split across writes: keep the prefix and
				// finish it on the next call.
				t.n = copy(t.pending[:], buf)
				break
			}
			out = append(out, '\\', 'x', hexDigits[buf[0]>>4], hexDigits[buf[0]&0xf])
			buf = buf[1:]
			continue
		}
		switch {
		case r == '\n' || r == '\t':
			out = append(out, byte(r))
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f):
			out = append(out, '\\', 'x', hexDigits[(r>>4)&0xf], hexDigits[r&0xf])
		default:
			out = append(out, buf[:size]...)
		}
		buf = buf[size:]
	}
	if len(out) > 0 {
		if _, err := t.dst.Write(out); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}
