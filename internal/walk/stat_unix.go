//go:build !windows

/*
Copyright (C) Philip Schlump, 2012-2026.

MIT Licensed.
*/

package walk

import (
	"os"
	"syscall"
)

// statOwner extracts uid/gid from a FileInfo on UNIX.
func statOwner(fi os.FileInfo) (int, int) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid), int(st.Gid)
	}
	return 0, 0
}

// statDev extracts the device id for tar -l (one-file-system).
func statDev(fi os.FileInfo) (uint64, bool) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Dev), true
	}
	return 0, false
}

// statID extracts the (device, inode) pair that identifies a hard-link
// family.
func statID(fi os.FileInfo) (uint64, uint64, bool) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Dev), uint64(st.Ino), true
	}
	return 0, 0, false
}

// statNLink extracts the link count.
func statNLink(fi os.FileInfo) (uint32, bool) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint32(st.Nlink), true
	}
	return 0, false
}
