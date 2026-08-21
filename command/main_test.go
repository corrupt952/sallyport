package command

import (
	"os"
	"syscall"
	"testing"
)

// TestMain gives the package a umask and a home of its own, for the reasons the
// workspace package's does: t.TempDir asks for 0777, and the walk that checks a
// path only stops at a home that exists.
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
