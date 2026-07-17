package command

import (
	"os"
	"strings"
	"testing"

	"github.com/google/subcommands"
)

// The export command must send warnings to stderr, never stdout: stdout is
// eval'd by the shell, so a warning there would be executed as a command.
func TestExportCommandRoutesWarningsToStderr(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("__SALLYPORT_STATE", "")
	dir := t.TempDir()
	writeConfig(t, dir) // present but never trusted
	t.Chdir(dir)

	outFile, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	errFile, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	stdout, stderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = outFile, errFile
	status := runCommand(t, &ExportCommand{}, "zsh")
	os.Stdout, os.Stderr = stdout, stderr
	_ = outFile.Close()
	_ = errFile.Close()

	if status != subcommands.ExitSuccess {
		t.Fatalf("export returned %v, want ExitSuccess", status)
	}

	outBytes, err := os.ReadFile(outFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	errBytes, err := os.ReadFile(errFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(errBytes), "is not trusted") {
		t.Errorf("warning not routed to stderr: %q", errBytes)
	}
	if strings.Contains(string(outBytes), "is not trusted") {
		t.Errorf("warning leaked into the eval'd stdout: %q", outBytes)
	}
}
