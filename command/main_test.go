package command

import (
	"os"
	"syscall"
	"testing"
)

// TestMain fixes the umask before any test runs, for the reason the workspace
// package's does: t.TempDir asks for 0777, and under a 0002 umask the
// workspaces these tests build arrive group-writable and are refused.
func TestMain(m *testing.M) {
	syscall.Umask(0o022)
	os.Exit(m.Run())
}
