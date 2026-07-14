package command

import (
	"context"
	"flag"
	"fmt"

	"github.com/google/subcommands"
)

// Version is set during build using ldflags.
var Version string

type VersionCommand struct{}

func (*VersionCommand) Name() string     { return "version" }
func (*VersionCommand) Synopsis() string { return "Print ws version" }
func (*VersionCommand) Usage() string {
	return "version: Print ws version\n"
}

func (*VersionCommand) SetFlags(f *flag.FlagSet) {}

func (*VersionCommand) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	fmt.Println(Version)
	return subcommands.ExitSuccess
}
