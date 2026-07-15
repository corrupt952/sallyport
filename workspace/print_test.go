package workspace

import (
	"bytes"
	"testing"
)

// The progress helpers must write to the injected writer, so callers (and
// tests) can capture output instead of leaking it to the real stdout.
func TestProgressWritesToInjectedWriter(t *testing.T) {
	var buf bytes.Buffer
	out = &buf
	t.Cleanup(func() { out = nil })

	Info("info %d", 1)
	Ok("ok %s", "x")
	Warn("warn")

	want := "  [ .. ] info 1\n  [ OK ] ok x\n  [ !! ] warn\n"
	if got := buf.String(); got != want {
		t.Errorf("progress output = %q, want %q", got, want)
	}
}
