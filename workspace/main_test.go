package workspace

import (
	"os"
	"syscall"
	"testing"
)

// TestMain gives the package a umask and a home of its own.
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
