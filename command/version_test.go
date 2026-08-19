package command

import (
	"os"
	"testing"

	"github.com/google/subcommands"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = f
	fn()
	os.Stdout = saved
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	out, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// The ldflags-injected version is what every release binary prints, and nothing
// else in the suite exercises it.
func TestVersionPrintsInjectedVersion(t *testing.T) {
	saved := Version
	Version = "v9.9.9-test"
	t.Cleanup(func() { Version = saved })

	out := captureStdout(t, func() {
		if got := runCommand(t, &VersionCommand{}); got != subcommands.ExitSuccess {
			t.Errorf("version: got %v, want ExitSuccess", got)
		}
	})
	if want := "v9.9.9-test\n"; out != want {
		t.Errorf("version output = %q, want %q", out, want)
	}
}
