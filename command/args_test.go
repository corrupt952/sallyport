package command

import (
	"context"
	"flag"
	"os"
	"testing"

	"github.com/google/subcommands"
)

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

// runCommand parses args into a fresh FlagSet the way subcommands.Execute would.
func runCommand(t *testing.T, cmd subcommands.Command, args ...string) subcommands.ExitStatus {
	t.Helper()
	fs := flag.NewFlagSet(cmd.Name(), flag.ContinueOnError)
	cmd.SetFlags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatalf("parse %v: %v", args, err)
	}
	return cmd.Execute(context.Background(), fs)
}

func TestShellArgValidation(t *testing.T) {
	silenceOutput(t)
	cmds := map[string]subcommands.Command{
		"export": &ExportCommand{},
		"hook":   &HookCommand{},
	}
	rejected := [][]string{
		{},               // missing shell name
		{"fish"},         // unsupported shell
		{"zsh", "extra"}, // too many args
	}
	for name, cmd := range cmds {
		for _, shell := range []string{"zsh", "bash"} {
			if got := runCommand(t, cmd, shell); got != subcommands.ExitSuccess {
				t.Errorf("%s %s: got %v, want ExitSuccess", name, shell, got)
			}
		}
		for _, args := range rejected {
			if got := runCommand(t, cmd, args...); got != subcommands.ExitUsageError {
				t.Errorf("%s %v: got %v, want ExitUsageError", name, args, got)
			}
		}
	}
}

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
