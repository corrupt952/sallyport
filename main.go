package main

import (
	"context"
	"flag"
	"os"

	"github.com/google/subcommands"

	"github.com/corrupt952/sallyport/command"
)

func main() {
	subcommands.Register(&command.CreateCommand{}, "")
	subcommands.Register(&command.HookCommand{}, "")
	subcommands.Register(&command.ExportCommand{}, "")
	subcommands.Register(&command.TrustCommand{}, "")
	subcommands.Register(&command.UntrustCommand{}, "")
	subcommands.Register(&command.VersionCommand{}, "")
	subcommands.Register(subcommands.HelpCommand(), "")
	subcommands.Register(subcommands.CommandsCommand(), "")

	flag.Parse()
	os.Exit(int(subcommands.Execute(context.Background())))
}
