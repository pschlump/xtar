/*
Copyright (C) Philip Schlump, 2012-2026.

BSD 3 Clause Licensed.
*/

// Package term is the thin terminal layer the prompts need: turning
// off echo while a password is read, the way the native tools hide
// secrets.  It works on the real terminal flags (termios) rather than
// any external dependency, and degrades to a no-op when standard
// input is not a terminal — a piped password still reads.
package term

import (
	"os"
	"syscall"
	"unsafe"
)

// NoEcho turns off ECHO on the standard input terminal and returns
// the function that restores the previous state.  The secret can then
// be read as an ordinary line while staying invisible; the caller
// prints a newline once reading is done.  When standard input is not
// a terminal (or the ioctl is unavailable) the returned function is a
// no-op and the caller simply reads in the clear.
func NoEcho() (restore func()) {
	fd := int(os.Stdin.Fd())
	var old syscall.Termios
	if _, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd),
		ioctlReadTermios, uintptr(unsafe.Pointer(&old)), 0, 0, 0); errno != 0 {
		return func() {}
	}
	hidden := old
	hidden.Lflag &^= syscall.ECHO
	if _, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd),
		ioctlWriteTermios, uintptr(unsafe.Pointer(&hidden)), 0, 0, 0); errno != 0 {
		return func() {}
	}
	return func() {
		syscall.Syscall6(syscall.SYS_IOCTL, uintptr(fd),
			ioctlWriteTermios, uintptr(unsafe.Pointer(&old)), 0, 0, 0)
	}
}
