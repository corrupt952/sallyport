package command

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/google/subcommands"

	"github.com/corrupt952/sallyport/workspace"
)

type ExportCommand struct {
	quiet bool
}

func (*ExportCommand) Name() string     { return "export" }
func (*ExportCommand) Synopsis() string { return "Print env diff for the current directory" }
func (*ExportCommand) Usage() string {
	return "export [-quiet] <zsh|bash>: Print env diff for the current directory (used by the hook)\n"
}

func (c *ExportCommand) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&c.quiet, "quiet", false, "suppress warnings (used by the per-prompt hook)")
}

func (c *ExportCommand) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	if f.NArg() != 1 || (f.Arg(0) != "zsh" && f.Arg(0) != "bash") {
		fmt.Fprint(os.Stderr, c.Usage())
		return subcommands.ExitUsageError
	}
	pwd, err := os.Getwd()
	if err != nil {
		return fail(err)
	}
	result, err := workspace.BuildExportScriptForShell(pwd, c.quiet, f.Arg(0))
	if err != nil {
		return fail(err)
	}
	// Warnings go to stderr so they never contaminate the script the shell
	// evals from stdout.
	for _, w := range result.Warnings {
		fmt.Fprintln(os.Stderr, w)
	}
	fmt.Print(result.Script)
	return subcommands.ExitSuccess
}
