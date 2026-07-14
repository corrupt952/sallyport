package command

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/google/subcommands"

	"github.com/corrupt952/sallyport/workspace"
)

type PruneCommand struct{}

func (*PruneCommand) Name() string     { return "prune" }
func (*PruneCommand) Synopsis() string { return "Remove trust records of deleted configs" }
func (*PruneCommand) Usage() string {
	return "prune: Remove trust records whose config file no longer exists\n"
}

func (*PruneCommand) SetFlags(f *flag.FlagSet) {}

func (c *PruneCommand) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	if f.NArg() != 0 {
		fmt.Fprint(os.Stderr, c.Usage())
		return subcommands.ExitUsageError
	}
	if err := workspace.Prune(); err != nil {
		return fail(err)
	}
	return subcommands.ExitSuccess
}
