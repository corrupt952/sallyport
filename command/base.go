// Package command implements the sallyport subcommands.
package command

import (
	"fmt"
	"os"

	"github.com/google/subcommands"
)

func fail(err error) subcommands.ExitStatus {
	fmt.Fprintf(os.Stderr, "  [FAIL] %s\n", err)
	return subcommands.ExitFailure
}
