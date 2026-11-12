/*
Copyright (C) Philip Schlump, 2012-2026.

BSD 3 Clause Licensed.
*/

package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/pschlump/xtar/internal/eng"
	"github.com/pschlump/xtar/internal/pat"
	"github.com/pschlump/xtar/internal/walk"
	"github.com/pschlump/xtar/internal/zipfmt"
)

// Sevenz is the 7-Zip dialect.  7z's grammar is its own: a bare
// command word first, then switches written as -oDIR/-pPASS with the
// value attached.  7z reads every format the engine reads; what it
// writes is chosen by -t or the archive name (the native .7z format
// is a later milestone).
func Sevenz(name string, argv []string) int {
	e := &env{name: name}

	var positional []string
	var outDir, password, typeName string
	var includes, excludes []*pat.Pattern
	var recurse, assumeYes bool
	level := -1
	method := -1

	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if !strings.HasPrefix(a, "-") || a == "-" {
			positional = append(positional, a)
			continue
		}
		body := a[1:]
		if body == "" {
			continue
		}
		switch body[0] {
		case 'o':
			if len(body) < 2 {
				return e.fatal("-o needs an attached directory (as in -ooutdir)")
			}
			outDir = body[1:]
		case 'p':
			if len(body) < 2 {
				password = promptLine("Enter password (will not be hidden until the terminal layer lands): ")
			} else {
				password = body[1:]
			}
		case 'x':
			v := strings.TrimPrefix(body[1:], "!")
			if p, err := pat.Compile(v); err == nil {
				excludes = append(excludes, p)
			}
		case 'i':
			if p, err := pat.Compile(body[1:]); err == nil {
				includes = append(includes, p)
			}
		case 't':
			if len(body) < 2 { // separate form: -t zip
				if i+1 < len(argv) {
					i++
					typeName = argv[i]
				}
			} else {
				typeName = body[1:]
			}
		case 'm':
			// -mx9 / -mx=9 / -m0=...: only the level is honored
			v := strings.TrimPrefix(body, "mx")
			v = strings.TrimPrefix(v, "=")
			if len(v) >= 1 && v[0] >= '0' && v[0] <= '9' {
				level = int(v[0] - '0')
			}
		case 'r':
			recurse = true
		case 'y':
			assumeYes = true
		default:
			// the long tail of 7z switches: accept quietly
		}
	}
	_ = assumeYes

	if len(positional) < 1 {
		return e.fatal("usage: %s <command> [<switches>...] <archive> [<files>...]", name)
	}
	cmd := positional[0]
	var args []string
	if len(positional) > 1 {
		args = positional[1:]
	}
	if len(args) < 1 {
		return e.fatal("the %s command needs an archive name", cmd)
	}
	archive := args[0]
	files := args[1:]

	switch cmd {
	case "a", "u":
		return sevenzAdd(e, archive, files, typeName, password, level, method, recurse, includes, excludes, cmd == "u")
	case "x", "e":
		return sevenzExtract(e, archive, files, password, outDir, cmd == "e", includes, excludes)
	case "l":
		return sevenzList(e, archive, includes, excludes)
	case "t":
		a, err := eng.OpenFile(archive, password)
		if err != nil {
			return e.fatal("%v", err)
		}
		if err := eng.Test(a, os.Stdout, true); err != nil {
			return e.fatal("%v", err)
		}
	case "d":
		if len(files) == 0 {
			return e.fatal("the d command needs at least one pattern")
		}
		pats, err := compilePatterns(files)
		if err != nil {
			return e.fatal("%v", err)
		}
		if _, err := eng.Update(&eng.UpdateOpts{Path: archive, Delete: pats, Warn: e.warn}); err != nil {
			return e.fatal("%v", err)
		}
	default:
		return e.fatal("unknown command %q (want a, x, e, l, t, u, or d)", cmd)
	}

	if e.warns > 0 {
		return exitWarn
	}
	return exitOK
}

// sevenzAdd creates or extends an archive; 7z recurses by default.
func sevenzAdd(e *env, archive string, files []string, typeName, password string, level, method int, recurse bool, includes, excludes []*pat.Pattern, updateOnly bool) int {
	container := ""
	codec := ""
	switch typeName {
	case "":
	case "zip":
		container = "zip"
	case "tar":
		container = "tar"
	case "cpio":
		container = "cpio"
	case "gzip", "bzip2", "lz4", "compress":
		codec = typeName
	default:
		return e.fatal("-t%s: unsupported archive type", typeName)
	}
	if method < 0 {
		method = int(zipfmt.MethodDeflate)
	}

	wopts := walk.Opts{
		Files:    files,
		Recurse:  true, // 7z walks directories by default
		Follow:   false,
		Symlinks: true,
		Include:  includes,
		Exclude:  excludes,
		Warn:     e.warn,
		Notice:   e.note,
	}
	_ = recurse // -r/-r- make no difference while recursion is forced

	if _, err := os.Stat(archive); err == nil && len(files) > 0 {
		res, err := eng.Update(&eng.UpdateOpts{
			Path:      archive,
			Walk:      wopts,
			Update:    updateOnly,
			Password:  password,
			ZipMethod: method,
			Warn:      e.warn,
		})
		if err != nil {
			return e.fatal("%v", err)
		}
		fmt.Fprintf(os.Stderr, "Updating archive: %s (%d file(s) added)\n", archive, res.Appended)
		return exitOK
	}
	a, err := eng.Create(&eng.CreateOpts{
		Path:             archive,
		Container:        container,
		Codec:            codec,
		Bare:             codec != "",
		ZipMethod:        method,
		ZipPassword:      password,
		Level:            level,
		DefaultContainer: "zip",
		Walk:             wopts,
	})
	if err != nil {
		return e.fatal("%v", err)
	}
	fmt.Fprintf(os.Stderr, "Creating archive: %s (%d members)\n", archive, len(a.Members))
	return exitOK
}

func sevenzExtract(e *env, archive string, files []string, password, outDir string, flat bool, includes, excludes []*pat.Pattern) int {
	a, err := eng.OpenFile(archive, password)
	if err != nil {
		return e.fatal("%v", err)
	}
	for _, n := range a.Notes {
		e.warnf("%s", n)
	}
	pats, err := compilePatterns(files)
	if err != nil {
		return e.fatal("%v", err)
	}
	pats = append(pats, includes...)
	eo := &eng.ExtractOpts{
		Dest:      orDefault(outDir, "."),
		Include:   pats,
		Exclude:   excludes,
		Flatten:   flat,
		Overwrite: eng.OvAlways, // -y is 7z's default posture
		Warn:      e.warn,
	}
	if err := eng.Extract(a, eo); err != nil {
		return e.fatal("%v", err)
	}
	return exitOK
}

func sevenzList(e *env, archive string, includes, excludes []*pat.Pattern) int {
	a, err := eng.OpenFile(archive, "")
	if err != nil {
		return e.fatal("%v", err)
	}
	for _, n := range a.Notes {
		e.warnf("%s", n)
	}
	eng.List(a, &eng.ListOpts{Out: os.Stdout, Style: "7z", Verbose: 1, Include: includes, Exclude: excludes})
	return exitOK
}
