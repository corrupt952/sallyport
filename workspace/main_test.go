package workspace

import (
	"os"
	"syscall"
	"testing"
)

// TestMain fixes the umask before any test runs. t.TempDir creates the
// directory it returns with os.Mkdir(dir, 0o777), so under the 0002 that Debian
// and Ubuntu give interactive users it arrives group-writable, and the path
// checks refuse every workspace inside it -- correctly, and for a reason no
// test here is about. Setting it once before m.Run leaves nothing to race
// with: no test changes it afterwards.
func TestMain(m *testing.M) {
	syscall.Umask(0o022)
	os.Exit(m.Run())
}
