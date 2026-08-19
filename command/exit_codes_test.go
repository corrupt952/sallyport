package command

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/subcommands"

	"github.com/corrupt952/sallyport/workspace"
)

// A command that reports success after the underlying operation failed is the
// worst outcome for a tool driven from CI and shell functions: the caller
// branches on the exit code. A failure nobody prints is the same problem seen
// from the user's side, so every case below pins both.

func assertFailed(t *testing.T, name string, status subcommands.ExitStatus, out capture) {
	t.Helper()
	if status != subcommands.ExitFailure {
		t.Errorf("%s: got %v, want ExitFailure", name, status)
	}
	if !strings.Contains(out.stderr, "[FAIL]") {
		t.Errorf("%s: failed without telling the user, stderr = %q", name, out.stderr)
	}
}

func runFailing(t *testing.T, cmd subcommands.Command, args ...string) {
	t.Helper()
	var status subcommands.ExitStatus
	out := captureOutput(t, func() { status = runCommand(t, cmd, args...) })
	assertFailed(t, cmd.Name(), status, out)
}

func TestTrustFailsOnUnparseableConfig(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	dir := t.TempDir()
	if err := os.WriteFile(workspace.ConfigPath(dir), []byte(`{"env": `), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)

	runFailing(t, &TrustCommand{})
	if workspace.IsTrusted(workspace.ConfigPath(dir)) {
		t.Error("unparseable config was trusted")
	}
}

func TestUntrustFailsWithoutGrant(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	dir := t.TempDir()
	writeConfig(t, dir)
	t.Chdir(dir)

	runFailing(t, &UntrustCommand{})
}

// Running trust or untrust where no config exists is far more common than
// running it on a broken one, and it takes the other branch of the same check.
func TestTrustAndUntrustFailWithoutConfig(t *testing.T) {
	for _, cmd := range []subcommands.Command{&TrustCommand{}, &UntrustCommand{}} {
		t.Run(cmd.Name(), func(t *testing.T) {
			t.Setenv("XDG_DATA_HOME", t.TempDir())
			t.Chdir(t.TempDir()) // an isolated tree with no config anywhere upward

			runFailing(t, cmd)
		})
	}
}

// Pointing XDG_DATA_HOME at a regular file makes every path below it unusable,
// which fails the store check without the test needing to know the store layout.
func TestPruneFailsOnUnusableTrustStore(t *testing.T) {
	base := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(base, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_DATA_HOME", base)

	runFailing(t, &PruneCommand{})
}

func TestCreateFailsWhenConfigExists(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	dir := t.TempDir()
	writeConfig(t, dir)
	t.Chdir(dir)

	runFailing(t, &CreateCommand{})
}
