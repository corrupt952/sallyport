package command

import (
	"context"
	"flag"
	"fmt"

	"github.com/google/subcommands"

	"github.com/corrupt952/sallyport/workspace"
)

type CurrentCommand struct{}

func (*CurrentCommand) Name() string     { return "current" }
func (*CurrentCommand) Synopsis() string { return "Print current workspace name" }
func (*CurrentCommand) Usage() string {
	return "current: Print current workspace name (exit 1 if none)\n"
}

func (*CurrentCommand) SetFlags(f *flag.FlagSet) {}

// Failure stays silent: prompt integrations call this on every render and
// must not see noise on stderr when outside a workspace.
func (c *CurrentCommand) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	name, err := workspace.CurrentName()
	if err != nil {
		return subcommands.ExitFailure
	}
	fmt.Println(name)
	return subcommands.ExitSuccess
}
