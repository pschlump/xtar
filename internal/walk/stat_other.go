//go:build windows

/*
Copyright (C) Philip Schlump, 2012-2026.

BSD 3 Clause Licensed.
*/

package walk

import "os"

// statOwner is the non-UNIX stub.
func statOwner(_ os.FileInfo) (int, int) { return 0, 0 }

// statDev is the non-UNIX stub.
func statDev(_ os.FileInfo) (uint64, bool) { return 0, false }

// statID is the non-UNIX stub.
func statID(_ os.FileInfo) (uint64, uint64, bool) { return 0, 0, false }

// statNLink is the non-UNIX stub.
func statNLink(_ os.FileInfo) (uint32, bool) { return 0, false }
