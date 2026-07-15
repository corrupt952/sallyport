package command

import (
	"context"
	"flag"
	"os"

	"github.com/google/subcommands"

	"github.com/corrupt952/sallyport/workspace"
)

type UntrustCommand struct{}

func (*UntrustCommand) Name() string     { return "untrust" }
func (*UntrustCommand) Synopsis() string { return "Revoke approval of the nearest .sallyport.jsonc" }
func (*UntrustCommand) Usage() string {
	return "untrust: Revoke approval of the nearest .sallyport.jsonc\n" +
		"         (an already-applied environment stays until you next leave and re-enter)\n"
}

func (*UntrustCommand) SetFlags(f *flag.FlagSet) {}

func (c *UntrustCommand) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	pwd, err := os.Getwd()
	if err != nil {
		return fail(err)
	}
	path, status := nearestConfig(f, pwd, c.Usage())
	if path == "" {
		return status
	}
	if err := workspace.Untrust(path); err != nil {
		return fail(err)
	}
	return subcommands.ExitSuccess
}
