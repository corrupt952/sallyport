package workspace

import (
	"fmt"
	"io"
	"os"
)

// out receives progress messages. A nil value is resolved to os.Stdout on each
// call rather than captured once, so a caller that swaps the real stdout is
// still honored; tests set it to a buffer to assert on messages instead of
// leaking them into the test log.
var out io.Writer

func progress(format string, a ...any) {
	dst := out
	if dst == nil {
		dst = os.Stdout
	}
	_, _ = fmt.Fprintf(dst, format, a...)
}

func Info(format string, a ...any) { progress("  [ .. ] "+format+"\n", a...) }
func Ok(format string, a ...any)   { progress("  [ OK ] "+format+"\n", a...) }
func Warn(format string, a ...any) { progress("  [ !! ] "+format+"\n", a...) }
