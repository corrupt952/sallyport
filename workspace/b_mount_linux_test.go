//go:build linux

package workspace

import "syscall"

func bMount(dir string) error   { return syscall.Mount("tmpfs", dir, "tmpfs", 0, "") }
func bUnmount(dir string) error { return syscall.Unmount(dir, 0) }
