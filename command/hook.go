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
	return "hook zsh: Print the shell hook (add eval \"$(sallyport hook zsh)\" to .zshrc)\n"
}

func (*HookCommand) SetFlags(f *flag.FlagSet) {}

func (c *HookCommand) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	if f.NArg() != 1 || f.Arg(0) != "zsh" {
		fmt.Fprint(os.Stderr, c.Usage())
		return subcommands.ExitUsageError
	}
	script, err := workspace.ZshHook()
	if err != nil {
		return fail(err)
	}
	fmt.Print(script)
	return subcommands.ExitSuccess
}
