/*
Copyright (C) Philip Schlump, 2012-2026.

BSD 3 Clause Licensed.
*/

package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/pschlump/xtar/internal/eng"
)

// unzipSpecs is the Info-ZIP unzip option surface.
var unzipSpecs = []opt{
	{long: "print", short: 'p'},
	{long: "list", short: 'l'},
	{long: "show-version", short: 'v'},
	{long: "test", short: 't'},
	{long: "directory", short: 'd', arg: true},
	{long: "exclude", short: 'x', arg: true},
	{long: "overwrite", short: 'o'},
	{long: "never-overwrite", short: 'n'},
	{long: "junk", short: 'j'},
	{long: "quiet", short: 'q'},
	{long: "password", short: 'P', arg: true},
	{long: "text", short: 'a'},
	{long: "zipinfo-mode", short: 'Z'},
	{long: "encoding", short: 'O', arg: true}, // -O: charset of stored names
	{long: "help", short: 'h'},
}

// Unzip is the Info-ZIP unzip dialect.  -Z switches to zipinfo mode.
func Unzip(name string, argv []string) int {
	e := &env{name: name}
	st := newArgStream(unzipSpecs, argv, false)

	var password, dest, encoding string
	var operands, excludes []string
	var print, list, verbose, test, overwrite, never, junk, quiet, zipinfoMode bool

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
		case o.short == 'p':
			print = true
		case o.short == 'l':
			list = true
		case o.short == 'v':
			verbose = true
		case o.short == 't':
			test = true
		case o.short == 'd':
			dest = t.value
		case o.short == 'x':
			excludes = append(excludes, t.value)
		case o.short == 'o':
			overwrite = true
		case o.short == 'n':
			never = true
		case o.short == 'j':
			junk = true
		case o.short == 'q':
			quiet = true
		case o.short == 'P':
			password = t.value
		case o.short == 'Z':
			zipinfoMode = true
		case o.short == 'O':
			encoding = t.value
		default:
			// -a/-h: accepted, no effect
		}
	}
	if zipinfoMode {
		return Zipinfo("zipinfo", operands)
	}
	if len(operands) < 1 {
		return e.fatal("need an archive (usage: unzip archive [files...])")
	}
	archive := operands[0]
	patterns := operands[1:]

	if password == "" {
		// unzip asks for the password when the archive needs one and
		// none was supplied.
		if pa, err := eng.OpenFile(archive, ""); err == nil {
			pa.Close()
		} else if strings.Contains(err.Error(), "password") {
			password = promptLine("Enter password: ")
		}
	}
	a, err := eng.OpenFile(archive, password)
	if err != nil {
		return e.fatal("%v", err)
	}
	defer a.Close()
	if err := a.SetEncoding(encoding); err != nil {
		return e.fatal("%v", err)
	}
	for _, n := range a.Notes {
		e.warnf("%s", n)
	}
	pats, err := compilePatterns(patterns)
	if err != nil {
		return e.fatal("%v", err)
	}
	exPats, err := compilePatterns(excludes)
	if err != nil {
		return e.fatal("%v", err)
	}

	switch {
	case test:
		if err := eng.Test(a, os.Stdout, !quiet); err != nil {
			return e.fatal("%v", err)
		}
		if !quiet {
			fmt.Fprintf(os.Stderr, "No errors detected in %s\n", archive)
		}
	case list, verbose && !print:
		lo := &eng.ListOpts{Out: os.Stdout, Style: "unzip", Include: pats, Exclude: exPats, Warn: e.warn}
		if verbose {
			lo.Verbose = 1
		}
		eng.List(a, lo)
	case print:
		eo := &eng.ExtractOpts{
			ToStdout:  true,
			Include:   pats,
			Exclude:   exPats,
			Flatten:   junk,
			Overwrite: eng.OvAlways,
			Warn:      e.warn,
		}
		if err := eng.Extract(a, eo); err != nil {
			return e.fatal("%v", err)
		}
	default:
		eo := &eng.ExtractOpts{
			Dest:      orDefault(dest, "."),
			Include:   pats,
			Exclude:   exPats,
			Flatten:   junk,
			Overwrite: eng.OvPrompt,
			Prompt:    promptReplace,
			Warn:      e.warn,
		}
		if overwrite {
			eo.Overwrite = eng.OvAlways
		}
		if never {
			eo.Overwrite = eng.OvNever
		}
		if !quiet && eo.Overwrite == eng.OvPrompt && !isTerminal() {
			// No tty to answer prompts: unzip in a pipe skips and warns.
			eo.Overwrite = eng.OvNever
		}
		if err := eng.Extract(a, eo); err != nil {
			return e.fatal("%v", err)
		}
	}

	if e.warns > 0 {
		return exitWarn
	}
	return exitOK
}

// Zipinfo is the zipinfo dialect (unzip -Z): listings in zipinfo's
// own table shape.
func Zipinfo(name string, argv []string) int {
	e := &env{name: name}
	st := newArgStream(zipinfoSpecs, argv, false)

	var archive string
	var namesOnly, header, verbose bool
	var excludes []string

	for {
		t, arg, err := st.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return e.fatal("%v", err)
		}
		if t == nil {
			if archive == "" {
				archive = arg
			}
			continue
		}
		o := t.o
		switch {
		case o.short == '1':
			namesOnly = true
		case o.short == 'h':
			header = true
		case o.short == 'v':
			verbose = true
		case o.short == 'x':
			excludes = append(excludes, t.value)
		default:
			// -m/-s/-t/-M/-l/-z: listing shapes not distinguished here
		}
	}
	if archive == "" {
		return e.fatal("need an archive (usage: zipinfo archive)")
	}
	a, err := eng.OpenFile(archive, "")
	if err != nil {
		return e.fatal("%v", err)
	}
	defer a.Close()
	for _, n := range a.Notes {
		e.warnf("%s", n)
	}
	exPats, err := compilePatterns(excludes)
	if err != nil {
		return e.fatal("%v", err)
	}
	lo := &eng.ListOpts{Out: os.Stdout, Style: "zipinfo", Exclude: exPats, Warn: e.warn}
	switch {
	case namesOnly:
		lo.Verbose = 0
		lo.Style = "unzip" // -1: plain names
	case verbose:
		lo.Verbose = 2
	case header:
		lo.Verbose = 0
	default:
		lo.Verbose = 1
	}
	eng.List(a, lo)
	if e.warns > 0 {
		return exitWarn
	}
	return exitOK
}

var zipinfoSpecs = []opt{
	{long: "names-only", short: '1'},
	{long: "header", short: 'h'},
	{long: "verbose", short: 'v'},
	{long: "medium", short: 'm'},
	{long: "short", short: 's'},
	{long: "totals", short: 't'},
	{long: "exclude", short: 'x', arg: true},
	{long: "zip-comment", short: 'z'},
	{long: "long-listing", short: 'l'},
}

// promptReplace adapts the engine's replace prompt to the CLI.
func promptReplace(question string) string {
	return promptLine(question)
}

// isTerminal reports whether there is a controlling terminal to
// answer prompts with (/dev/null is a character device too, so the
// Stat trick is not enough).
func isTerminal() bool {
	f, err := os.Open("/dev/tty")
	if err != nil {
		return false
	}
	f.Close()
	return true
}
