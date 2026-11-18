//go:build !windows

/*
Copyright (C) Philip Schlump, 2012-2026.

MIT Licensed.
*/

package eng

import (
	"fmt"
	"io/fs"
	"syscall"
)

// currentUmask returns (and restores) the process umask.
func currentUmask() fs.FileMode {
	old := syscall.Umask(0)
	syscall.Umask(old)
	return fs.FileMode(old & 0o777)
}

// makeSpecial creates a fifo or device node (the latter needs root).
func makeSpecial(dest, what string, mode fs.FileMode, dev uint32, euid int) error {
	if what == "fifo" {
		return syscall.Mkfifo(dest, uint32(mode.Perm()))
	}
	if euid != 0 {
		return fmt.Errorf("device nodes can only be created by root")
	}
	kind := uint32(syscall.S_IFBLK)
	if what == "device-char" {
		kind = syscall.S_IFCHR
	}
	return syscall.Mknod(dest, kind|uint32(mode.Perm()), int(dev))
}
