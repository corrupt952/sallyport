package command

import (
	"os"
	"strings"
	"testing"

	"github.com/google/subcommands"

	"github.com/corrupt952/sallyport/workspace"
)

// A-104: with no config anywhere above, both commands have to name the
// directory the search started from. The shell's idea of where it is and the
// user's do not always agree, and the search only goes upwards from there.
func TestTrustAndUntrustReportWhereTheSearchStarted(t *testing.T) {
	commands := map[string]subcommands.Command{
		"trust":   &TrustCommand{},
		"untrust": &UntrustCommand{},
	}
	for name, cmd := range commands {
		t.Run(name, func(t *testing.T) {
			t.Setenv("XDG_DATA_HOME", t.TempDir())
			t.Chdir(t.TempDir())
			pwd, err := os.Getwd()
			if err != nil {
				t.Fatal(err)
			}

			var status subcommands.ExitStatus
			got := captureOutput(t, func() { status = runCommand(t, cmd) })
			if status != subcommands.ExitFailure {
				t.Errorf("got status %v, want ExitFailure", status)
			}
			for _, want := range []string{workspace.ConfigFileName, pwd, "upwards"} {
				if !strings.Contains(got.stderr, want) {
					t.Errorf("stderr %q does not mention %q", got.stderr, want)
				}
			}
		})
	}
}
