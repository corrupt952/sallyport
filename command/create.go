package command

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/google/subcommands"

	"github.com/corrupt952/sallyport/workspace"
)

type CreateCommand struct{}

func (*CreateCommand) Name() string     { return "create" }
func (*CreateCommand) Synopsis() string { return "Create a sallyport.jsonc in the current directory" }
func (*CreateCommand) Usage() string {
	return "create: Create a sallyport.jsonc in the current directory\n"
}

func (*CreateCommand) SetFlags(f *flag.FlagSet) {}

func (c *CreateCommand) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	if f.NArg() != 0 {
		fmt.Fprint(os.Stderr, c.Usage())
		return subcommands.ExitUsageError
	}
	pwd, err := os.Getwd()
	if err != nil {
		return fail(err)
	}
	if err := workspace.Create(pwd); err != nil {
		return fail(err)
	}
	return subcommands.ExitSuccess
}
