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
	"github.com/pschlump/xtar/internal/member"
	"github.com/pschlump/xtar/internal/walk"
	"github.com/pschlump/xtar/internal/zipfmt"
)

// zipSpecs is the Info-ZIP zip option surface.  zip's grammar is
// plain short options (bundled or not) with the archive as the first
// operand.
var zipSpecs = []opt{
	{long: "recurse", short: 'r'},
	{long: "encrypt", short: 'e'},
	{long: "password", short: 'P', arg: true},
	{long: "quiet", short: 'q'},
	{long: "verbose", short: 'v'},
	{long: "update", short: 'u'},
	{long: "freshen", short: 'f'},
	{long: "delete", short: 'd'},
	{long: "move", short: 'm'},
	{long: "test", short: 'T'},
	{long: "junk", short: 'j'},
	{long: "symlinks", short: 'y'},
	{long: "archive-comment", short: 'z', arg: true},
	{long: "compression", short: 'Z', arg: true},
	{long: "exclude", short: 'x', arg: true},
	{long: "include", short: 'i', arg: true},
	{long: "level0", short: '0'},
	{long: "level1", short: '1'},
	{long: "level2", short: '2'},
	{long: "level3", short: '3'},
	{long: "level4", short: '4'},
	{long: "level5", short: '5'},
	{long: "level6", short: '6'},
	{long: "level7", short: '7'},
	{long: "level8", short: '8'},
	{long: "level9", short: '9'},
	{long: "to-crlf", short: 'l'},
	{long: "to-lf", short: 'a'},
	{long: "no-dir-entries", short: 'D'},
	{long: "update-add", short: 'U'},
	{long: "help", short: 'h'},
	{long: "from-date", short: 't', arg: true},
	{long: "suffix", short: 'n', arg: true},
	{long: "temp-dir", short: 'b', arg: true},
}

// Zip is the Info-ZIP zip dialect: create or update a zip archive.
func Zip(name string, argv []string) int {
	e := &env{name: name}
	st := newArgStream(zipSpecs, argv, false)

	var password, comment string
	var operands, excludes, includes []string
	var recurse, encrypt, quiet, verbose bool
	var update, freshen, deleteMode, moveMode, test, junk bool
	var symlinks, noDirEntries bool
	level := -1
	method := -1
	tested := false

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
		case o.short == 'r':
			recurse = true
		case o.short == 'e':
			encrypt = true
		case o.short == 'P':
			password = t.value
		case o.short == 'q':
			quiet = true
		case o.short == 'v':
			verbose = true
		case o.short == 'u':
			update = true
		case o.short == 'f':
			freshen = true
		case o.short == 'd':
			deleteMode = true
		case o.short == 'm':
			moveMode = true
		case o.short == 'T':
			test = true
		case o.short == 'j':
			junk = true
		case o.short == 'y':
			symlinks = true
		case o.short == 'D':
			noDirEntries = true
		case o.short == 'z':
			comment = t.value
		case o.short == 'x':
			excludes = append(excludes, t.value)
		case o.short == 'i':
			includes = append(includes, t.value)
		case o.short == 'Z':
			switch t.value {
			case "store":
				method = int(zipfmt.MethodStore)
			case "deflate", "":
				method = int(zipfmt.MethodDeflate)
			case "bzip2":
				method = int(zipfmt.MethodBZip2)
			default:
				return e.fatal("unknown compression method %q (want store, deflate, or bzip2)", t.value)
			}
		case o.short == '0':
			method = int(zipfmt.MethodStore)
		case o.short >= '1' && o.short <= '9':
			method = int(zipfmt.MethodDeflate)
			level = int(o.short - '0')
		default:
			// -l/-a/-t/-n/-b/-h/-U: accepted, no effect in this model
		}
	}
	if len(operands) < 1 {
		return e.fatal("need a zip file name (usage: zip archive [files...])")
	}
	archive := operands[0]
	files := operands[1:]

	if encrypt && password == "" {
		p1 := promptPassword("Enter password: ")
		p2 := promptPassword("Verify password: ")
		if p1 == "" || p1 != p2 {
			return e.fatal("zero-length password or passwords do not match")
		}
		password = p1
	}

	exPats, err := compilePatterns(excludes)
	if err != nil {
		return e.fatal("%v", err)
	}
	inPats, err := compilePatterns(includes)
	if err != nil {
		return e.fatal("%v", err)
	}

	wopts := walk.Opts{
		Files:    files,
		Recurse:  recurse,
		Follow:   !symlinks,
		Symlinks: symlinks,
		Junk:     junk,
		NoDirs:   noDirEntries,
		Include:  inPats,
		Exclude:  exPats,
		Warn:     e.warn,
		Notice:   e.note,
	}

	switch {
	case deleteMode:
		if len(files) == 0 {
			return e.fatal("zip -d needs at least one pattern")
		}
		pats, err := compilePatterns(files)
		if err != nil {
			return e.fatal("%v", err)
		}
		res, err := eng.Update(&eng.UpdateOpts{Path: archive, Delete: pats, Warn: e.warn})
		if err != nil {
			return e.fatal("%v", err)
		}
		if !quiet {
			fmt.Fprintf(os.Stderr, "deleting %d file(s)\n", res.Deleted)
		}

	case test && len(files) == 0:
		// zip -T on an existing archive with nothing to add: test only.
		tested = true
		if err := verifyZip(archive, password); err != nil {
			return e.fatal("%v", err)
		}
		if !quiet {
			fmt.Fprintf(os.Stderr, "test of %s OK\n", archive)
		}

	default:
		if _, err := os.Stat(archive); err == nil && len(files) > 0 {
			// Adding to an existing archive: update in place.
			res, err := eng.Update(&eng.UpdateOpts{
				Path:      archive,
				Walk:      wopts,
				Update:    update || freshen,
				Password:  password,
				ZipMethod: method,
				Warn:      e.warn,
			})
			if err != nil {
				return e.fatal("%v", err)
			}
			if !quiet {
				fmt.Fprintf(os.Stderr, "updating: %s (%d file(s) added)\n", archive, res.Appended)
			}
			break
		}
		a, err := eng.Create(&eng.CreateOpts{
			Path:             archive,
			Container:        "zip",
			ZipMethod:        method,
			ZipPassword:      password,
			ZipComment:       comment,
			Level:            level,
			DefaultContainer: "zip",
			Walk:             wopts,
		})
		if err != nil {
			return e.fatal("%v", err)
		}
		if verbose && !quiet {
			fmt.Fprintf(os.Stderr, "  adding: %s (%d members)\n", archive, len(a.Members))
		}
	}

	if moveMode && !deleteMode {
		// -m: remove the inputs after a successful add.
		for _, f := range files {
			if err := os.Remove(f); err != nil {
				e.warnf("%v", err)
			}
		}
	}

	if test && !tested {
		if err := verifyZip(archive, password); err != nil {
			return e.fatal("%v", err)
		}
		if !quiet {
			fmt.Fprintf(os.Stderr, "test of %s OK\n", archive)
		}
	}

	if e.warns > 0 {
		return exitWarn
	}
	return exitOK
}

// verifyZip re-opens the archive and checks every member's stored CRC.
func verifyZip(path, password string) error {
	a, err := eng.OpenFile(path, password)
	if err != nil {
		return err
	}
	defer a.Close()
	for i := range a.Members {
		m := &a.Members[i]
		if m.Raw == nil || m.Kind == member.Directory {
			continue
		}
		if m.Raw.CRC != zipfmt.CRC32(m.Data) {
			return fmt.Errorf("%s: bad CRC for %s", path, m.Name)
		}
	}
	return nil
}
