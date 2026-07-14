package command

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/google/subcommands"

	"github.com/corrupt952/sallyport/workspace"
)

type TrustCommand struct{}

func (*TrustCommand) Name() string     { return "trust" }
func (*TrustCommand) Synopsis() string { return "Approve the nearest .sallyport.jsonc" }
func (*TrustCommand) Usage() string {
	return "trust: Approve the nearest .sallyport.jsonc so its env gets applied\n"
}

func (*TrustCommand) SetFlags(f *flag.FlagSet) {}

func (c *TrustCommand) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	path, status := nearestConfig(f, c.Usage())
	if path == "" {
		return status
	}
	if err := workspace.Trust(path); err != nil {
		return fail(err)
	}
	return subcommands.ExitSuccess
}

// nearestConfig resolves the config governing cwd, shared by trust/untrust.
func nearestConfig(f *flag.FlagSet, usage string) (string, subcommands.ExitStatus) {
	if f.NArg() != 0 {
		fmt.Fprint(os.Stderr, usage)
		return "", subcommands.ExitUsageError
	}
	pwd, err := os.Getwd()
	if err != nil {
		return "", fail(err)
	}
	root := workspace.FindRoot(pwd)
	if root == "" {
		return "", fail(fmt.Errorf("no %s found from %s upwards", workspace.ConfigFileName, pwd))
	}
	return workspace.ConfigPath(root), subcommands.ExitSuccess
}
