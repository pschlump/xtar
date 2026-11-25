//go:build !windows

/*
Copyright (C) Philip Schlump, 2012-2026.

MIT Licensed.
*/

package ageio

import (
	"errors"
	"os"
	"syscall"
)

// syncDir flushes dir's entries so a name just renamed into it is on
// disk.  The directory is opened read-only and synced like a file.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return ignoreUnsupported(err)
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return ignoreUnsupported(err)
}

// ignoreUnsupported drops the errors of a filesystem that cannot sync
// a directory — EINVAL, or "not supported" — since the rename already
// happened, so there is nothing left to flush.
func ignoreUnsupported(err error) error {
	if errors.Is(err, syscall.EINVAL) || errors.Is(err, errors.ErrUnsupported) {
		return nil
	}
	return err
}
