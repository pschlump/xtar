//go:build windows

/*
Copyright (C) Philip Schlump, 2012-2026.

MIT Licensed.
*/

package ageio

// syncDir is the non-UNIX stub: the os package opens a directory
// read-only, and Windows rejects flushing such a handle.  The rename
// that precedes it is atomic there on its own.
func syncDir(string) error { return nil }
