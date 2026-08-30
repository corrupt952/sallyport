package command

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/google/subcommands"

	"github.com/corrupt952/sallyport/workspace"
)

type HookCommand struct{}

func (*HookCommand) Name() string     { return "hook" }
func (*HookCommand) Synopsis() string { return "Print the shell hook" }
func (*HookCommand) Usage() string {
	return "hook <zsh|bash>: Print the shell hook (eval it from the shell's rc file)\n"
}

func (*HookCommand) SetFlags(f *flag.FlagSet) {}

func (c *HookCommand) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	if f.NArg() != 1 || (f.Arg(0) != "zsh" && f.Arg(0) != "bash") {
		fmt.Fprint(os.Stderr, c.Usage())
		return subcommands.ExitUsageError
	}
	var script string
	var err error
	switch f.Arg(0) {
	case "zsh":
		script, err = workspace.ZshHook()
	case "bash":
		script, err = workspace.BashHook()
	}
	if err != nil {
		return fail(err)
	}
	fmt.Print(script)
	return subcommands.ExitSuccess
}
