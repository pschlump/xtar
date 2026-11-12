/*
Copyright (C) Philip Schlump, 2012-2026.

BSD 3 Clause Licensed.
*/

// xtar is one multi-call binary (busybox-style): the tool it behaves
// as is chosen by the name it was invoked under — tar, cpio, zip,
// unzip, 7z, zipinfo, or xtar for its own unified dialect.  The
// dialect controls only the command-line syntax; which archive format
// is read or written is decided by content and file-name extension.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/pschlump/xtar/internal/cli"
)

func main() {
	name := filepath.Base(os.Args[0])
	argv := os.Args[1:]

	var code int
	switch name {
	case "tar", "gtar":
		code = cli.Tar(name, argv)
	case "xtar":
		code = cli.Xtar(name, argv)
	case "cpio":
		code = cli.NotYet(name, "cpio", "M2")
	case "zip", "zipinfo", "unzip":
		code = cli.NotYet(name, name, "M3")
	case "7z", "7za", "7zr":
		code = cli.NotYet(name, name, "M3")
	default:
		fmt.Fprintf(os.Stderr, "%s: unknown dialect — invoke as tar, gtar, cpio, zip, unzip, 7z, 7za, 7zr, zipinfo, or xtar\n", name)
		code = 2
	}
	os.Exit(code)
}
