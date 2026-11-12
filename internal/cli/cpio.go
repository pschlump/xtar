/*
Copyright (C) Philip Schlump, 2012-2026.

BSD 3 Clause Licensed.
*/

package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/pschlump/xtar/internal/eng"
	"github.com/pschlump/xtar/internal/walk"
)

// cpioSpecs is the GNU cpio option surface (see the README).  The
// stdio defaults are the cpio idioms: copy-in reads stdin, copy-out
// writes stdout, and the file list always comes from stdin on -o/-p.
var cpioSpecs = []opt{
	{long: "extract", short: 'i'},
	{long: "create", short: 'o'},
	{long: "pass-through", short: 'p'},
	{long: "make-directories", short: 'd'},
	{long: "list", short: 't'},
	{long: "verbose", short: 'v'},
	{long: "unconditional", short: 'u'},
	{long: "preserve-modification-time", short: 'm'},
	{long: "nonmatching", short: 'f'},
	{long: "dereference", short: 'L'},
	{long: "append", short: 'A'},
	{long: "file", short: 'F', arg: true},
	{long: "input-archive", short: 'I', arg: true},  // GNU cpio: -I only
	{long: "output-archive", short: 'O', arg: true}, // GNU cpio: -O only
	{long: "force-local"},
	{long: "format", short: 'H', arg: true},
	{long: "pattern-file", short: 'E', arg: true},
	{long: "owner", short: 'R', arg: true},
	{long: "quiet"},
	{long: "no-absolute-filenames"},
	{long: "block-size", short: 'B'},
	{long: "io-size", short: 'C', arg: true},
}

// Cpio is the cpio dialect.  It returns the process exit code.
func Cpio(name string, argv []string) int {
	e := &env{name: name}
	st := newArgStream(cpioSpecs, argv, true)

	var mode string // i, o, p
	var archive, input, output, format, ownerSpec string
	var patternFiles, operands []string
	var makeDirs, listOnly, verbose, unconditional, preserveMtime bool
	var nonmatching, appendMode, quiet, dereference bool

	for {
		t, arg, err := st.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return e.fatal("%v", err)
		}
		if t == nil {
			operands = append(operands, arg)
			continue
		}
		o := t.o
		switch {
		case o.short == 'i', o.short == 'o', o.short == 'p':
			mode = string(o.short)
		case o.short == 'd':
			makeDirs = true
		case o.short == 't':
			listOnly = true
		case o.short == 'v':
			verbose = true
		case o.short == 'u':
			unconditional = true
		case o.short == 'm':
			preserveMtime = true
		case o.short == 'f':
			nonmatching = true
		case o.short == 'L':
			dereference = true
		case o.short == 'A':
			appendMode = true
		case o.short == 'F':
			archive = t.value
		case o.short == 'I':
			input = t.value
		case o.short == 'O':
			output = t.value
		case o.short == 'H':
			format = t.value
		case o.short == 'E':
			patternFiles = append(patternFiles, t.value)
		case o.short == 'R':
			ownerSpec = t.value
		case o.short == 'B', o.long == "io-size", o.long == "force-local", o.long == "no-absolute-filenames":
			// blocking / io size: no-op in the whole-buffer model;
			// force-local: remote ":host:" syntax not used, accept;
			// no-absolute-filenames: already the default behavior
		case o.long == "quiet":
			quiet = true
		default:
			return e.fatal("unhandled option %s (internal)", t.name)
		}
	}
	if mode == "" {
		return e.fatal("you must specify one of the -i, -o, or -p options")
	}
	if ownerSpec != "" {
		return e.fatal("-R/--owner is not supported yet")
	}

	// -I/-O refine -F; with none of them cpio talks stdio.
	file := archive
	if input != "" {
		file = input
	}
	if output != "" {
		file = output
	}

	// The copy-out/pass-through name source is always stdin, and
	// enumeration is the caller's job: cpio never recurses into a
	// directory operand (that is what find is for).
	wopts := walk.Opts{
		StdinList: true,
		Follow:    dereference,
		Symlinks:  !dereference,
		Warn:      e.warn,
		Notice:    e.note,
	}
	if verbose && !quiet {
		wopts.OnName = func(n string) { fmt.Fprintln(os.Stderr, n) }
	}

	var cpFormat, tarFormat, container string
	switch format {
	case "", "newc", "crc", "odc":
		cpFormat = format
		container = "cpio"
	case "bin", "binary":
		return e.fatal("-H bin: the binary cpio variant is read-only")
	case "tar":
		container, tarFormat = "tar", "v7"
	case "ustar":
		container, tarFormat = "tar", "ustar"
	default:
		return e.fatal("invalid archive format %q (want bin, odc, newc, crc, tar, or ustar)", format)
	}
	if cpFormat == "" {
		cpFormat = "newc"
	}

	switch mode {
	case "o":
		if appendMode {
			if file == "" {
				return e.fatal("-A requires -F, -I, or -O")
			}
			uo := &eng.UpdateOpts{Path: file, Walk: wopts, Warn: e.warn}
			if container == "cpio" {
				uo.Format = cpFormat
			} else {
				uo.Format = tarFormat
			}
			if _, err := eng.Update(uo); err != nil {
				return e.fatal("%v", err)
			}
			break
		}
		a, err := eng.Create(&eng.CreateOpts{
			Path:             orDefault(file, "-"),
			Container:        container,
			CpioFormat:       cpFormat,
			TarFormat:        tarFormat,
			DefaultContainer: "cpio",
			EmptyOK:          true, // a trailer-only archive is valid cpio
			Walk:             wopts,
		})
		if err != nil {
			return e.fatal("%v", err)
		}
		if !quiet {
			blocks := (a.CompSize + 511) / 512
			noun := "s"
			if blocks == 1 {
				noun = ""
			}
			fmt.Fprintf(os.Stderr, "%d block%s\n", blocks, noun)
		}

	case "i":
		path := file
		if path == "" {
			path = "-"
		}
		a, err := eng.OpenFile(path, "")
		if err != nil {
			return e.fatal("%v", err)
		}
		for _, n := range a.Notes {
			e.warnf("%s", n)
		}
		patSrc := operands
		for _, pf := range patternFiles {
			list, err := readList(pf, false)
			if err != nil {
				return e.fatal("%v", err)
			}
			patSrc = append(patSrc, list...)
		}
		pats, err := compilePatterns(patSrc)
		if err != nil {
			return e.fatal("%v", err)
		}
		if listOnly {
			lo := &eng.ListOpts{Out: os.Stdout, Style: "cpio", Include: pats, Exclude: nil}
			if verbose {
				lo.Verbose = 1
			}
			eng.List(a, lo)
			break
		}
		eo := &eng.ExtractOpts{
			Dest:      ".",
			Overwrite: eng.OvIfOlder, // cpio default: replace only older copies
			Touch:     !preserveMtime,
			NoDirs:    !makeDirs,
			Warn:      e.warn,
		}
		if unconditional {
			eo.Overwrite = eng.OvAlways
		}
		if nonmatching {
			eo.Exclude = pats
		} else {
			eo.Include = pats
		}
		if verbose && !quiet {
			eo.OnName = func(n string) { fmt.Fprintln(os.Stderr, n) }
		}
		if err := eng.Extract(a, eo); err != nil {
			return e.fatal("%v", err)
		}

	case "p":
		if len(operands) == 0 {
			return e.fatal("pass-through needs a destination directory")
		}
		dst := operands[0]
		if len(operands) > 1 {
			e.warnf("extra operands after %s ignored", dst)
		}
		mems, err := walk.Gather(&wopts)
		if err != nil {
			return e.fatal("%v", err)
		}
		eo := &eng.ExtractOpts{
			Dest:      dst,
			Overwrite: eng.OvIfOlder,
			Touch:     !preserveMtime,
			NoDirs:    !makeDirs,
			Warn:      e.warn,
		}
		if unconditional {
			eo.Overwrite = eng.OvAlways
		}
		if verbose && !quiet {
			eo.OnName = func(n string) { fmt.Fprintln(os.Stderr, n) }
		}
		if err := eng.Extract(&eng.Archive{Format: "cpio", Members: mems}, eo); err != nil {
			return e.fatal("%v", err)
		}
	}

	if e.warns > 0 {
		return exitWarn
	}
	return exitOK
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
