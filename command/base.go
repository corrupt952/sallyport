// Package command implements the sallyport subcommands.
package command

import (
	"fmt"
	"io"
	"os"

	"github.com/google/subcommands"
)

// errOut receives command-level error messages. A nil value is resolved to
// os.Stderr on each call rather than captured once, so a caller that swaps the
// real stderr is still honored; tests set it to a buffer to assert on failure
// messages.
var errOut io.Writer

func fail(err error) subcommands.ExitStatus {
	dst := errOut
	if dst == nil {
		dst = os.Stderr
	}
	fmt.Fprintf(dst, "  [FAIL] %s\n", err)
	return subcommands.ExitFailure
}
