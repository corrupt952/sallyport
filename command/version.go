package command

import (
	"context"
	"flag"
	"fmt"
	"runtime/debug"

	"github.com/google/subcommands"
)

// Version is set during build using ldflags. Installs via `go install ...@vX`
// don't get ldflags, so the module version from build info is the fallback.
var Version string

func version() string {
	if Version != "" {
		return Version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return "unknown"
}

type VersionCommand struct{}

func (*VersionCommand) Name() string     { return "version" }
func (*VersionCommand) Synopsis() string { return "Print sallyport version" }
func (*VersionCommand) Usage() string {
	return "version: Print sallyport version\n"
}

func (*VersionCommand) SetFlags(f *flag.FlagSet) {}

func (*VersionCommand) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	fmt.Println(version())
	return subcommands.ExitSuccess
}
