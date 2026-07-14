package command

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/google/subcommands"

	"github.com/corrupt952/sallyport/workspace"
)

type ExportCommand struct{}

func (*ExportCommand) Name() string     { return "export" }
func (*ExportCommand) Synopsis() string { return "Print env diff for the current directory" }
func (*ExportCommand) Usage() string {
	return "export zsh: Print env diff for the current directory (used by the hook)\n"
}

func (*ExportCommand) SetFlags(f *flag.FlagSet) {}

func (c *ExportCommand) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	if f.NArg() != 1 || f.Arg(0) != "zsh" {
		fmt.Fprint(os.Stderr, c.Usage())
		return subcommands.ExitUsageError
	}
	pwd, err := os.Getwd()
	if err != nil {
		return fail(err)
	}
	script, err := workspace.BuildExportScript(pwd)
	if err != nil {
		return fail(err)
	}
	fmt.Print(script)
	return subcommands.ExitSuccess
}
