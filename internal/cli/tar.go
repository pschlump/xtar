/*
Copyright (C) Philip Schlump, 2012-2026.

BSD 3 Clause Licensed.
*/

package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pschlump/xtar/internal/eng"
	"github.com/pschlump/xtar/internal/member"
	"github.com/pschlump/xtar/internal/walk"
)

// tarSpecs is the GNU tar option surface M1 implements.  Options the
// project deliberately does not carry (incrementals, multi-volume,
// xattrs…) are absent rather than silently ignored; unrecognized
// options error.
var tarSpecs = []opt{
	{long: "create", short: 'c'},
	{long: "append", short: 'r'},
	{long: "concatenate", short: 'A'},
	{long: "catenate", short: 'A'},
	{long: "diff", short: 'd'},
	{long: "compare", short: 'd'},
	{long: "delete"},
	{long: "extract", short: 'x'},
	{long: "get", short: 'x'},
	{long: "list", short: 't'},
	{long: "update", short: 'u'},
	{long: "file", short: 'f', arg: true},
	{long: "directory", short: 'C', arg: true},
	{long: "verbose", short: 'v'},
	{long: "gzip", short: 'z'},
	{long: "gunzip", short: 'z'},
	{long: "ungzip", short: 'z'},
	{long: "bzip2", short: 'j'},
	{long: "bunzip2", short: 'j'},
	{long: "xz", short: 'J'},
	{long: "unxz", short: 'J'},
	{long: "compress", short: 'Z'},
	{long: "uncompress", short: 'Z'},
	{long: "lz4"},
	{long: "zstd"},
	{long: "lzip"},
	{long: "format", arg: true},
	{long: "exclude", arg: true},
	{long: "exclude-from", short: 'X', arg: true},
	{long: "strip-components", arg: true},
	{long: "files-from", short: 'T', arg: true},
	{long: "null"},
	{long: "to-stdout", short: 'O'},
	{long: "preserve-perms", short: 'p'},
	{long: "same-permissions", short: 'p'},
	{long: "touch", short: 'm'},
	{long: "modification-time", short: 'm'},
	{long: "keep-old-files", short: 'k'},
	{long: "keep-newer-files"},
	{long: "overwrite"},
	{long: "skip-old-files"},
	{long: "no-same-owner"},
	{long: "same-owner"},
	{long: "no-same-permissions"},
	{long: "interactive", short: 'w'},
	{long: "confirmation", short: 'w'},
	{long: "verify", short: 'W'},
	{long: "owner", arg: true},
	{long: "group", arg: true},
	{long: "numeric-owner"},
	{long: "no-recursion"},
	{long: "recursion"},
	{long: "sparse", short: 'S'},
	{long: "one-file-system", short: 'l'},
	{long: "dereference", short: 'h'},
	{long: "transform", arg: true},
	{long: "totals"},
	{long: "blocking-factor", short: 'b', arg: true},
	{long: "record-size", arg: true},
}

// operand is a non-option argument plus the -C directory in effect
// where it appeared (GNU tar semantics: -C applies to the operands
// that follow it).
type operand struct {
	val string
	dir string
}

// Tar is the tar/gtar dialect.  It returns the process exit code.
func Tar(name string, argv []string) int {
	e := &env{name: name}
	st := newArgStream(tarSpecs, argv, true)

	var op string
	opCount := 0
	file := os.Getenv("TAPE")
	if file == "" {
		file = "-" // stdin/stdout, the bsdtar default
	}
	var codec, format string
	var verbosity, strip int
	var nullSep, toStdout, keepPerms, touch, noSameOwner bool
	var interactive, verify, totals, numericOwner bool
	var noRecursion, oneFS, follow, sparse bool
	var ownerSpec, groupSpec string
	overwrite := eng.OvAlways
	chdir := "" // running -C prefix for operands
	var operands []operand
	var exclPatSrc, transforms []string
	var exclFrom []string

	for {
		t, arg, err := st.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return e.fatal("%v", err)
		}
		if t == nil {
			operands = append(operands, operand{val: arg, dir: chdir})
			continue
		}
		o := t.o
		switch {
		case o.short == 'c', o.short == 'r', o.short == 'u', o.short == 'A',
			o.short == 'x', o.short == 't', o.short == 'd',
			o.long == "delete":
			op = string(o.short)
			if o.long == "delete" {
				op = "delete"
			}
			opCount++
		case o.short == 'f':
			file = t.value
		case o.short == 'C':
			// A running prefix, like cd: relative values stack, an
			// absolute value replaces the prefix.
			if chdir == "" || filepath.IsAbs(t.value) {
				chdir = t.value
			} else {
				chdir = filepath.Join(chdir, t.value)
			}
		case o.short == 'v':
			verbosity++
		case o.short == 'z':
			codec = "gzip"
		case o.short == 'j':
			codec = "bzip2"
		case o.short == 'Z':
			codec = "compress"
		case o.short == 'J':
			codec = "xz"
		case o.long == "lzma":
			return e.fatal("%v", eng.UnsupportedError("lzma (the .lzma-alone codec is the next M5 step)"))
		case o.long == "zstd":
			return e.fatal("%v", eng.UnsupportedError("zstd"))
		case o.long == "lzip":
			return e.fatal("%v", eng.UnsupportedError("lzip"))
		case o.long == "lz4":
			codec = "lz4"
		case o.long == "format":
			f, err := normalizeTarFormat(t.value)
			if err != nil {
				return e.fatal("%v", err)
			}
			format = f
		case o.long == "exclude":
			exclPatSrc = append(exclPatSrc, t.value)
		case o.short == 'X' || o.long == "exclude-from":
			exclFrom = append(exclFrom, t.value)
		case o.long == "strip-components":
			n, err := strconv.Atoi(t.value)
			if err != nil || n < 0 {
				return e.fatal("invalid --strip-components value %q", t.value)
			}
			strip = n
		case o.short == 'T' || o.long == "files-from":
			// Read here so each -T list inherits the -C prefix in
			// effect where the option appeared.
			list, err := readList(t.value, nullSep)
			if err != nil {
				return e.fatal("%v", err)
			}
			for _, n := range list {
				operands = append(operands, operand{val: n, dir: chdir})
			}
		case o.long == "null":
			nullSep = true
		case o.short == 'O':
			toStdout = true
		case o.short == 'p':
			keepPerms = true
		case o.long == "no-same-permissions":
			keepPerms = false
		case o.short == 'm':
			touch = true
		case o.short == 'k', o.long == "skip-old-files":
			overwrite = eng.OvNever
		case o.long == "keep-newer-files":
			overwrite = eng.OvIfOlder
		case o.long == "overwrite":
			overwrite = eng.OvAlways
		case o.long == "no-same-owner":
			noSameOwner = true
		case o.long == "same-owner":
			noSameOwner = false
		case o.short == 'w':
			interactive = true
		case o.short == 'W':
			verify = true
		case o.long == "owner":
			ownerSpec = t.value
		case o.long == "group":
			groupSpec = t.value
		case o.long == "numeric-owner":
			numericOwner = true
		case o.long == "no-recursion":
			noRecursion = true
		case o.long == "recursion":
			noRecursion = false
		case o.short == 'S':
			sparse = true
		case o.short == 'l':
			oneFS = true
		case o.short == 'h':
			follow = true
		case o.long == "transform":
			transforms = append(transforms, t.value)
		case o.long == "totals":
			totals = true
		case o.short == 'b', o.long == "record-size":
			// Blocking factor / record size: the whole-buffer model has
			// no blocking; accept and ignore like a no-op.
		default:
			return e.fatal("unhandled option %s (internal)", t.name)
		}
	}
	if opCount == 0 {
		return e.fatal("you must specify one of the -Acdrtux or --delete options")
	}
	if opCount > 1 {
		return e.fatal("conflicting archive operations")
	}

	for _, xf := range exclFrom {
		list, err := readList(xf, nullSep)
		if err != nil {
			return e.fatal("%v", err)
		}
		exclPatSrc = append(exclPatSrc, list...)
	}
	exclPats, err := compilePatterns(exclPatSrc)
	if err != nil {
		return e.fatal("%v", err)
	}
	transformFn, err := chainTransforms(transforms)
	if err != nil {
		return e.fatal("%v", err)
	}

	// The member-pattern view of the operands (read ops) or the file
	// view (write ops), plus shared walk options.
	patternSrc := make([]string, len(operands))
	files := make([]string, len(operands))
	for i, opnd := range operands {
		patternSrc[i] = opnd.val
		if opnd.dir != "" {
			files[i] = filepath.Join(opnd.dir, opnd.val)
		} else {
			files[i] = opnd.val
		}
	}
	wopts := walk.Opts{
		Files: files,
		// Member names are the operands as typed, relative to any -C
		// directory; files[] holds the joined filesystem paths.
		Names:        patternSrc,
		NamePolicy:   walk.TarNames, // GNU tar keeps ./f.txt, stores the . root
		NoRecursion:  noRecursion,
		Sparse:       sparse, // -S: store holes as extents
		Recurse:      !noRecursion,
		OneFS:        oneFS,
		Follow:       follow,
		Symlinks:     !follow,
		Exclude:      exclPats,
		NumericOwner: numericOwner,
		Transform:    transformFn,
		Warn:         e.warn,
		Notice:       e.note,
	}
	if verbosity > 0 {
		wopts.OnName = func(n string) { fmt.Println(n) }
	}
	if ownerSpec != "" {
		uid, err := parseOwnerArg(ownerSpec, true)
		if err != nil {
			return e.fatal("--owner: %v", err)
		}
		wopts.Owner, wopts.HaveOwner = uid, true
	}
	if groupSpec != "" {
		gid, err := parseOwnerArg(groupSpec, false)
		if err != nil {
			return e.fatal("--group: %v", err)
		}
		wopts.Group, wopts.HaveGroup = gid, true
	}

	switch op {
	case "c":
		a, err := eng.Create(&eng.CreateOpts{
			Path:             file,
			Container:        "tar",
			Codec:            codec,
			DefaultContainer: "tar",
			TarFormat:        format,
			Walk:             wopts,
		})
		if err != nil {
			return e.fatal("%v", err)
		}
		if totals {
			fmt.Printf("Total bytes written: %d (%s)\n", a.CompSize, humanBytes(a.CompSize))
		}
		if verify {
			if code := verifyArchive(e, file, a); code != exitOK {
				return code
			}
		}

	case "x", "t", "d":
		a, err := eng.OpenFile(file, "")
		if err != nil {
			return e.fatal("%v", err)
		}
		defer func() { _ = a.Close() }() // releases the codec chain for streamed archives
		for _, n := range a.Notes {
			e.warnf("%s", n)
		}
		inc, err := compilePatterns(patternSrc)
		if err != nil {
			return e.fatal("%v", err)
		}
		if op == "t" {
			lo := &eng.ListOpts{
				Out:     os.Stdout,
				Verbose: verbosity,
				Numeric: numericOwner,
				Style:   "tar",
				Include: inc,
				Exclude: exclPats,
				Strip:   strip,
				Warn:    e.warn,
			}
			if lo.Verbose > 1 {
				lo.Verbose = 1
			}
			eng.List(a, lo)
			break
		}
		if op == "d" {
			dir := chdir
			if dir == "" {
				dir = "."
			}
			if eng.Diff(a, dir, os.Stdout, e.warn) > 0 {
				e.warns++ // differences count as a warning exit
			}
			break
		}
		eo := &eng.ExtractOpts{
			Dest:        destFor(chdir),
			Include:     inc,
			Exclude:     exclPats,
			ToStdout:    toStdout,
			Strip:       strip,
			Transform:   transformFn,
			Overwrite:   overwrite,
			KeepPerms:   keepPerms,
			NoSameOwner: noSameOwner,
			Touch:       touch,
			Warn:        e.warn,
		}
		if verbosity > 0 {
			eo.OnName = func(n string) { fmt.Println(n) }
		}
		if interactive {
			eo.Confirm = func(n string) bool {
				ans := promptLine(fmt.Sprintf("extract %s? ", n))
				switch strings.ToLower(strings.TrimSpace(ans)) {
				case "y", "yes":
					return true
				}
				return false
			}
		}
		if err := eng.Extract(a, eo); err != nil {
			return e.fatal("%v", err)
		}

	case "r", "u", "A", "delete":
		uo := &eng.UpdateOpts{
			Path:   file,
			Format: format,
			Delete: exclPats,
			Update: op == "u",
			Warn:   e.warn,
		}
		uo.Walk = wopts
		uo.Walk.Files = files // -A/--delete take no files, but harmless
		switch op {
		case "r", "u":
			// files gathered via wopts
		case "A":
			uo.Walk = walk.Opts{Warn: e.warn}
			for _, opnd := range operands {
				if opnd.dir != "" {
					uo.Concat = append(uo.Concat, filepath.Join(opnd.dir, opnd.val))
				} else {
					uo.Concat = append(uo.Concat, opnd.val)
				}
			}
			if len(uo.Concat) == 0 {
				return e.fatal("no archive names given to concatenate")
			}
		case "delete":
			uo.Walk = walk.Opts{Warn: e.warn}
			if len(patternSrc) == 0 {
				return e.fatal("--delete needs at least one member name or pattern")
			}
			delpats, err := compilePatterns(patternSrc)
			if err != nil {
				return e.fatal("%v", err)
			}
			uo.Delete = delpats
		}
		res, err := eng.Update(uo)
		if err != nil {
			return e.fatal("%v", err)
		}
		if totals {
			fmt.Printf("Total bytes written: %d (%s)\n", res.Bytes, humanBytes(res.Bytes))
		}
	}

	if e.warns > 0 {
		return exitWarn
	}
	return exitOK
}

// destFor turns the running -C prefix into an extraction base
// directory.
func destFor(chdir string) string {
	if chdir == "" {
		return "."
	}
	return chdir
}

// verifyArchive implements -W: re-read the archive just written and
// compare it member-by-member with what we intended to store.
func verifyArchive(e *env, file string, want *eng.Archive) int {
	if file == "-" {
		e.warnf("cannot verify an archive written to standard output")
		return exitWarn
	}
	got, err := eng.OpenFile(file, "")
	if err != nil {
		e.warnf("verify failed: %v", err)
		return exitWarn
	}
	defer func() { _ = got.Close() }()
	i := 0
	var bad string
	err = got.Each(func(m *member.Member, _ io.Reader) error {
		if i >= len(want.Members) {
			return errVerifyStop
		}
		w := &want.Members[i]
		if w.Name != m.Name || w.Kind != m.Kind || w.DataSize() != m.DataSize() {
			bad = w.Name
			return errVerifyStop
		}
		i++
		return nil
	})
	if err != nil && !errors.Is(err, errVerifyStop) {
		e.warnf("verify failed: %v", err)
		return exitWarn
	}
	if err != nil || i != len(want.Members) {
		if bad == "" {
			e.warnf("verify: member count differs (wrote %d, read %d)", len(want.Members), i)
		} else {
			e.warnf("verify: %s differs", bad)
		}
		return exitWarn
	}
	return exitOK
}

// errVerifyStop ends verifyArchive's walk early without reporting a
// read failure.
var errVerifyStop = errors.New("verify stop")

func normalizeTarFormat(s string) (string, error) {
	switch s {
	case "gnu", "oldgnu":
		return "gnu", nil
	case "ustar":
		return "ustar", nil
	case "pax", "posix":
		return "pax", nil
	case "v7":
		return "v7", nil
	}
	return "", fmt.Errorf("unknown format %q (want gnu, ustar, pax, or v7)", s)
}
