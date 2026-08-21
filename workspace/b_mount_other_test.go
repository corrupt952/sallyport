//go:build !linux

package workspace

import "errors"

// Only the Linux case makes a mount of its own (B-62); everywhere else the case
// skips before it gets here.
func bMount(string) error   { return errors.New("mounting is only wired up on Linux") }
func bUnmount(string) error { return errors.New("mounting is only wired up on Linux") }
