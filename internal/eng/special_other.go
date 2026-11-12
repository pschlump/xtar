//go:build windows

/*
Copyright (C) Philip Schlump, 2012-2026.

BSD 3 Clause Licensed.
*/

package eng

import (
	"errors"
	"io/fs"
)

// currentUmask is the non-UNIX stub.
func currentUmask() fs.FileMode { return 0o022 }

// makeSpecial is the non-UNIX stub.
func makeSpecial(dest, what string, mode fs.FileMode, dev uint32, euid int) error {
	return errors.New("special files are not supported on this platform")
}
