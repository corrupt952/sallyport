package command

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/subcommands"

	"github.com/corrupt952/sallyport/workspace"
)

// Reporting success after the underlying operation failed is the worst outcome
// for a tool driven from CI and shell functions: the caller branches on the
// exit code and never sees the message. Each test below drives one command into
// a real failure and pins the status.

func TestTrustFailsOnUnparseableConfig(t *testing.T) {
	silenceOutput(t)
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	dir := t.TempDir()
	if err := os.WriteFile(workspace.ConfigPath(dir), []byte(`{"env": `), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)

	if got := runCommand(t, &TrustCommand{}); got != subcommands.ExitFailure {
		t.Errorf("trust: got %v, want ExitFailure", got)
	}
	if workspace.IsTrusted(workspace.ConfigPath(dir)) {
		t.Error("unparseable config was trusted")
	}
}

func TestUntrustFailsWithoutGrant(t *testing.T) {
	silenceOutput(t)
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	dir := t.TempDir()
	writeConfig(t, dir)
	t.Chdir(dir)

	if got := runCommand(t, &UntrustCommand{}); got != subcommands.ExitFailure {
		t.Errorf("untrust: got %v, want ExitFailure", got)
	}
}

// Pointing XDG_DATA_HOME at a regular file makes every path below it unusable,
// which fails the store check without the test needing to know the store layout.
func TestPruneFailsOnUnusableTrustStore(t *testing.T) {
	silenceOutput(t)
	base := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(base, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_DATA_HOME", base)

	if got := runCommand(t, &PruneCommand{}); got != subcommands.ExitFailure {
		t.Errorf("prune: got %v, want ExitFailure", got)
	}
}

func TestCreateFailsWhenConfigExists(t *testing.T) {
	silenceOutput(t)
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	dir := t.TempDir()
	writeConfig(t, dir)
	t.Chdir(dir)

	if got := runCommand(t, &CreateCommand{}); got != subcommands.ExitFailure {
		t.Errorf("create: got %v, want ExitFailure", got)
	}
}
