package workspace

import (
	"fmt"
	"os"
	"syscall"
	"testing"
)

// hookSubcommand is the first argument the zsh hook invokes the binary with.
// Every argument `go test` passes is a -test.* flag, so a bare word identifies
// the caller as a shell running the shim.
const hookSubcommand = "export"

func isHookReentry(args []string) bool {
	return len(args) > 0 && args[0] == hookSubcommand
}

// TestMain gives the package a umask and a home of its own, and refuses to run
// as the sallyport CLI.
//
// The refusal: ZshHook embeds os.Executable(), which under `go test` is this
// test binary, so a shim reaching a real shell has the shell run
// `workspace.test export ... zsh`. flag.Parse stops at that non-flag argument
// without complaining and the whole suite runs again, each round starting the
// next; CommandContext kills the zsh it started but not what that zsh already
// forked, so the recursion outlives the run as orphans.
//
// The umask: t.TempDir creates the directory it returns with
// os.Mkdir(dir, 0o777), so under the 0002 that Debian and Ubuntu give
// interactive users it arrives group-writable and the path checks refuse every
// workspace inside it -- correctly, and for a reason no test here is about.
//
// The home: the walk that checks a path stops at the home directory, and only
// there. Under a Nix builder HOME is /homeless-shelter, which does not exist,
// so no boundary can be established and the walk runs to the filesystem root --
// which inside the Linux build sandbox is owned by neither the build user nor
// root, and is refused. Pointing TMPDIR and HOME at one tree the tests own puts
// the boundary back above every directory they create.
//
// XDG_DATA_HOME is deliberately left alone: export_test.go gives each test its
// own trust store only when it finds none set, and setting one here would make
// the whole package share a single store.
func TestMain(m *testing.M) {
	if isHookReentry(os.Args[1:]) {
		// stdout is what the hook evals, so it stays empty and the reason goes to
		// stderr.
		fmt.Fprintf(os.Stderr, "%s: refusing to run as sallyport; a test let the zsh hook reach the test binary\n", os.Args[0])
		os.Exit(2)
	}
	syscall.Umask(0o022)
	base, err := os.MkdirTemp("", "sallyport-tests")
	if err != nil {
		panic(err)
	}
	if err := os.Setenv("TMPDIR", base); err != nil {
		panic(err)
	}
	if err := os.Setenv("HOME", base); err != nil {
		panic(err)
	}
	code := m.Run()
	_ = os.RemoveAll(base)
	os.Exit(code)
}
