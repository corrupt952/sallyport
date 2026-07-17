package command

import (
	"context"
	"flag"
	"os"
	"testing"

	"github.com/google/subcommands"
)

// silenceOutput redirects stdout/stderr to /dev/null for the duration of a test,
// so a command's usage text and script output don't clutter the test log.
func silenceOutput(t *testing.T) {
	t.Helper()
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	stdout, stderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = devnull, devnull
	t.Cleanup(func() {
		os.Stdout, os.Stderr = stdout, stderr
		_ = devnull.Close()
	})
}

// runCommand parses args into a fresh FlagSet the way subcommands.Execute would,
// then invokes the command directly.
func runCommand(t *testing.T, cmd subcommands.Command, args ...string) subcommands.ExitStatus {
	t.Helper()
	fs := flag.NewFlagSet(cmd.Name(), flag.ContinueOnError)
	cmd.SetFlags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatalf("parse %v: %v", args, err)
	}
	return cmd.Execute(context.Background(), fs)
}

// TestShellArgValidation covers export/hook, which demand exactly one "zsh" arg.
func TestShellArgValidation(t *testing.T) {
	silenceOutput(t)
	cmds := map[string]subcommands.Command{
		"export": &ExportCommand{},
		"hook":   &HookCommand{},
	}
	rejected := [][]string{
		{},               // missing shell name
		{"bash"},         // unsupported shell
		{"zsh", "extra"}, // too many args
	}
	for name, cmd := range cmds {
		for _, args := range rejected {
			if got := runCommand(t, cmd, args...); got != subcommands.ExitUsageError {
				t.Errorf("%s %v: got %v, want ExitUsageError", name, args, got)
			}
		}
	}
}

// TestNoArgCommandsRejectExtraArgs covers commands that take no positional args.
func TestNoArgCommandsRejectExtraArgs(t *testing.T) {
	silenceOutput(t)
	cmds := map[string]subcommands.Command{
		"create":  &CreateCommand{},
		"trust":   &TrustCommand{},
		"untrust": &UntrustCommand{},
		"prune":   &PruneCommand{},
		"version": &VersionCommand{},
	}
	for name, cmd := range cmds {
		if got := runCommand(t, cmd, "extra"); got != subcommands.ExitUsageError {
			t.Errorf("%s extra: got %v, want ExitUsageError", name, got)
		}
	}
}

// TestVersionSucceeds guards the happy path so the added arg check doesn't
// accidentally reject the normal invocation.
func TestVersionSucceeds(t *testing.T) {
	silenceOutput(t)
	if got := runCommand(t, &VersionCommand{}); got != subcommands.ExitSuccess {
		t.Errorf("version: got %v, want ExitSuccess", got)
	}
}
