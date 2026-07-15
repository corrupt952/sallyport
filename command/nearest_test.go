package command

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/subcommands"

	"github.com/corrupt952/sallyport/workspace"
)

func flagSet(t *testing.T, args ...string) *flag.FlagSet {
	t.Helper()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		t.Fatalf("parse %v: %v", args, err)
	}
	return fs
}

func writeConfig(t *testing.T, dir string) {
	t.Helper()
	if err := os.WriteFile(workspace.ConfigPath(dir), []byte(`{"env": {}}`), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestNearestConfigFound(t *testing.T) {
	silenceOutput(t)
	root := t.TempDir()
	writeConfig(t, root)
	sub := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	path, status := nearestConfig(flagSet(t), sub, "usage")
	if status != subcommands.ExitSuccess {
		t.Fatalf("got status %v, want ExitSuccess", status)
	}
	if want := workspace.ConfigPath(root); path != want {
		t.Errorf("got path %q, want %q", path, want)
	}
}

func TestNearestConfigNotFound(t *testing.T) {
	silenceOutput(t)
	pwd := t.TempDir() // an isolated tree with no config anywhere upward
	path, status := nearestConfig(flagSet(t), pwd, "usage")
	if path != "" {
		t.Errorf("got path %q, want empty", path)
	}
	if status != subcommands.ExitFailure {
		t.Errorf("got status %v, want ExitFailure", status)
	}
}

func TestNearestConfigRejectsExtraArgs(t *testing.T) {
	silenceOutput(t)
	path, status := nearestConfig(flagSet(t, "extra"), t.TempDir(), "usage")
	if path != "" {
		t.Errorf("got path %q, want empty", path)
	}
	if status != subcommands.ExitUsageError {
		t.Errorf("got status %v, want ExitUsageError", status)
	}
}

// TestTrustUntrustCommands exercises the full command path against a real,
// isolated workspace: XDG_DATA_HOME is redirected to a temp dir so trust
// records never touch the real home.
func TestTrustUntrustCommands(t *testing.T) {
	silenceOutput(t)
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	dir := t.TempDir()
	writeConfig(t, dir)
	t.Chdir(dir)

	path := workspace.ConfigPath(dir)
	if got := runCommand(t, &TrustCommand{}); got != subcommands.ExitSuccess {
		t.Fatalf("trust: got %v, want ExitSuccess", got)
	}
	if !workspace.IsTrusted(path) {
		t.Fatal("config not trusted after trust command")
	}
	if got := runCommand(t, &UntrustCommand{}); got != subcommands.ExitSuccess {
		t.Fatalf("untrust: got %v, want ExitSuccess", got)
	}
	if workspace.IsTrusted(path) {
		t.Fatal("config still trusted after untrust command")
	}
}
