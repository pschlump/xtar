//go:build linux

/*
Copyright (C) Philip Schlump, 2012-2026.

MIT Licensed.
*/

package term

import "syscall"

const (
	ioctlReadTermios  = syscall.TCGETS
	ioctlWriteTermios = syscall.TCSETS
)
