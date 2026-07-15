package command

import (
	"bytes"
	"errors"
	"testing"

	"github.com/google/subcommands"
)

// fail must write to the injected writer so tests can assert on error output
// without touching the real stderr.
func TestFailWritesToInjectedWriter(t *testing.T) {
	var buf bytes.Buffer
	errOut = &buf
	t.Cleanup(func() { errOut = nil })

	if got := fail(errors.New("boom")); got != subcommands.ExitFailure {
		t.Errorf("fail returned %v, want ExitFailure", got)
	}
	if want := "  [FAIL] boom\n"; buf.String() != want {
		t.Errorf("fail output = %q, want %q", buf.String(), want)
	}
}
