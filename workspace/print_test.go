package workspace

import (
	"bytes"
	"testing"
)

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
