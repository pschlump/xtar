//go:build !darwin && !linux

/*
Copyright (C) Philip Schlump, 2012-2026.

BSD 3 Clause Licensed.
*/

package term

// Termios ioctls are unknown here; NoEcho degrades to the no-op path
// (it only ever sees errno != 0 from an undefined constant anyway if
// the platform lacks SYS_IOCTL).
const (
	ioctlReadTermios  = 0
	ioctlWriteTermios = 0
)
