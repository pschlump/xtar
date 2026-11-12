/*
Copyright (C) Philip Schlump, 2012-2026.

BSD 3 Clause Licensed.
*/

package cli

import (
	"fmt"
	"os"
)

// NotYet is the placeholder for dialects the roadmap lands later
// (cpio in M2; zip, unzip, zipinfo, 7z in M3).  It fails loudly
// rather than pretending.
func NotYet(name, dialect, milestone string) int {
	fmt.Fprintf(os.Stderr, "%s: the %s dialect is not implemented yet (planned for %s of the README roadmap)\n", name, dialect, milestone)
	return exitFatal
}
