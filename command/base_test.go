package command

import (
	"bytes"
	"errors"
	"testing"

	"github.com/google/subcommands"
)

func TestFailWritesToInjectedWriter(t *testing.T) {
	var buf bytes.Buffer
	saved := errOut
	errOut = &buf
	t.Cleanup(func() { errOut = saved })

	if got := fail(errors.New("boom")); got != subcommands.ExitFailure {
		t.Errorf("fail returned %v, want ExitFailure", got)
	}
	if want := "  [FAIL] boom\n"; buf.String() != want {
		t.Errorf("fail output = %q, want %q", buf.String(), want)
	}
}

// Nothing sets errOut outside tests, so the nil fallback is the only path a real
// run takes. It must reach stderr exactly once and never stdout: the shell evals
// the stdout of export and hook.
func TestFailWithoutInjectedWriterWritesOnlyToStderr(t *testing.T) {
	var status subcommands.ExitStatus
	out := captureOutput(t, func() { status = fail(errors.New("boom")) })

	if status != subcommands.ExitFailure {
		t.Errorf("fail returned %v, want ExitFailure", status)
	}
	if want := "  [FAIL] boom\n"; out.stderr != want {
		t.Errorf("stderr = %q, want %q", out.stderr, want)
	}
	if out.stdout != "" {
		t.Errorf("failure message leaked into stdout: %q", out.stdout)
	}
}
