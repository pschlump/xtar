/*
Copyright (C) Philip Schlump, 2012-2026.

BSD 3 Clause Licensed.
*/

package cli

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/pschlump/xtar/internal/eng"
	"github.com/pschlump/xtar/internal/walk"
)

// xtarSpecs is the xtar dialect's superset flag surface (see the
// README): the options every native tool shares, spelled one way.
var xtarSpecs = []opt{
	{long: "directory", short: 'C', arg: true},
	{long: "output", short: 'o', arg: true},
	{long: "exclude", arg: true},
	{long: "strip-components", arg: true},
	{long: "flatten"},
	{long: "to-stdout", short: 'O'},
	{long: "format", arg: true},
	{long: "encoding", arg: true},
	{long: "stdin"},
	{long: "stdout"},
	{long: "sniff"},
	{long: "verbose", short: 'v'},
	{long: "owner", arg: true},
	{long: "group", arg: true},
	{long: "numeric-owner"},
}

// Xtar is xtar's own dialect: one verb set, every format.
func Xtar(name string, argv []string) int {
	e := &env{name: name}
	if len(argv) == 0 {
		usageXtar(name)
		return exitFatal
	}
	verb := argv[0]
	switch verb {
	case "-h", "--help":
		usageXtar(name)
		return exitOK
	case "--version":
		fmt.Println("xtar (development)")
		return exitOK
	case "--sniff":
		return sniffCmd(e, argv[1:])
	case "i":
		return infoCmd()
	case "c", "x", "l", "t":
	default:
		return e.fatal("unknown verb %q (want c, x, l, t, i, --sniff)", verb)
	}

	st := newArgStream(xtarSpecs, argv[1:], false)
	var dest string
	var strip, verbosity int
	var flatten, toStdout, useStdin, useStdout, numericOwner bool
	var exclSrc []string
	var container, tarFormat, codec, encoding string
	var ownerSpec, groupSpec string
	var operands []string

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
		case o.short == 'C', o.short == 'o':
			dest = t.value
		case o.long == "exclude":
			exclSrc = append(exclSrc, t.value)
		case o.long == "strip-components":
			n, err := strconv.Atoi(t.value)
			if err != nil || n < 0 {
				return e.fatal("invalid --strip-components value %q", t.value)
			}
			strip = n
		case o.long == "flatten":
			flatten = true
		case o.short == 'O':
			toStdout = true
		case o.long == "format":
			container, tarFormat, codec, err = splitXtarFormat(t.value)
			if err != nil {
				return e.fatal("%v", err)
			}
		case o.long == "encoding":
			encoding = t.value
		case o.long == "stdin":
			useStdin = true
		case o.long == "stdout":
			useStdout = true
		case o.short == 'v':
			verbosity++
		case o.long == "owner":
			ownerSpec = t.value
		case o.long == "group":
			groupSpec = t.value
		case o.long == "numeric-owner":
			numericOwner = true
		default:
			return e.fatal("unhandled option %s (internal)", t.name)
		}
	}
	if encoding != "" {
		return e.fatal("--encoding is not supported yet (it arrives with zip support, roadmap M3)")
	}
	if len(operands) == 0 {
		return e.fatal("no archive given")
	}

	exclPats, err := compilePatterns(exclSrc)
	if err != nil {
		return e.fatal("%v", err)
	}
	path := operands[0]
	if useStdin || useStdout {
		path = "-"
	}

	switch verb {
	case "c":
		if useStdin {
			return e.fatal("cannot create an archive on standard input")
		}
		if len(operands) < 2 {
			return e.fatal("no files given to archive")
		}
		wopts := walk.Opts{
			Files:        operands[1:],
			Recurse:      true,
			Symlinks:     true,
			Exclude:      exclPats,
			NumericOwner: numericOwner,
			Warn:         e.warn,
			Notice:       e.note,
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
		if _, err := eng.Create(&eng.CreateOpts{
			Path:             path,
			Container:        container,
			Codec:            codec,
			DefaultContainer: "tar",
			TarFormat:        tarFormat,
			Walk:             wopts,
		}); err != nil {
			return e.fatal("%v", err)
		}

	case "x":
		a, err := eng.OpenFile(path, "")
		if err != nil {
			return e.fatal("%v", err)
		}
		for _, n := range a.Notes {
			e.warnf("%s", n)
		}
		inc, err := compilePatterns(operands[1:])
		if err != nil {
			return e.fatal("%v", err)
		}
		eo := &eng.ExtractOpts{
			Dest:      dest,
			Include:   inc,
			Exclude:   exclPats,
			ToStdout:  toStdout,
			Flatten:   flatten,
			Strip:     strip,
			Overwrite: eng.OvAlways,
			Warn:      e.warn,
			Prompt:    promptLine,
		}
		if verbosity > 0 {
			eo.OnName = func(n string) { fmt.Println(n) }
		}
		if err := eng.Extract(a, eo); err != nil {
			return e.fatal("%v", err)
		}

	case "l":
		a, err := eng.OpenFile(path, "")
		if err != nil {
			return e.fatal("%v", err)
		}
		for _, n := range a.Notes {
			e.warnf("%s", n)
		}
		inc, err := compilePatterns(operands[1:])
		if err != nil {
			return e.fatal("%v", err)
		}
		eng.List(a, &eng.ListOpts{
			Out:     os.Stdout,
			Verbose: verbosity,
			Numeric: numericOwner,
			Style:   "tar",
			Include: inc,
			Exclude: exclPats,
			Strip:   strip,
		})

	case "t":
		for _, p := range operands {
			a, err := eng.OpenFile(p, "")
			if err != nil {
				e.warnf("%v", err)
				continue
			}
			if err := eng.Test(a, os.Stdout, verbosity > 0); err != nil {
				e.warnf("%s: %v", p, err)
			}
		}
	}

	if e.warns > 0 {
		return exitWarn
	}
	return exitOK
}

func usageXtar(name string) {
	fmt.Fprintf(os.Stderr, "usage: %s {c|x|l|t|i} [flags] ARCHIVE [MEMBERS...]\n       %s --sniff FILE...\n", name, name)
}

// sniffCmd is `xtar --sniff FILE...`.
func sniffCmd(e *env, files []string) int {
	if len(files) == 0 {
		return e.fatal("--sniff needs at least one file")
	}
	for _, f := range files {
		info, err := eng.SniffFile(f)
		if err != nil {
			e.warnf("%v", err)
			continue
		}
		layers := strings.Join(info.Layers, " → ")
		head := info.Format
		if info.Variant != "" {
			head = fmt.Sprintf("%s (%s)", head, info.Variant)
		}
		if layers != "" {
			head = layers + " → " + head
		}
		fmt.Printf("%s: %s : %d members, %s → %s\n",
			f, head, info.Members, humanBytes(info.CompSize), humanBytes(info.RawSize))
	}
	if e.warns > 0 {
		return exitWarn
	}
	return exitOK
}

// infoCmd is `xtar i`: what this build reads and writes.
func infoCmd() int {
	fmt.Println("containers: tar (read: v7, ustar, GNU, pax; write: gnu, ustar, pax, v7)")
	fmt.Println("containers: cpio, zip (planned — see README roadmap)")
	fmt.Println("codecs:     gzip, bzip2, compress (.Z), lz4")
	fmt.Println("planned:    xz, zstd, lzma, lzip, 7z containers (see README)")
	return exitOK
}

// splitXtarFormat accepts a container name, a tar variant, or the
// compound spelling "tar+gzip" / "tar+ustar".
func splitXtarFormat(s string) (container, tarFormat, codec string, err error) {
	switch s {
	case "tar", "cpio", "zip":
		return s, "", "", nil
	}
	if f, ferr := normalizeTarFormat(s); ferr == nil {
		return "tar", f, "", nil
	}
	if i := strings.IndexByte(s, '+'); i > 0 {
		switch c, rest := s[:i], s[i+1:]; c {
		case "tar":
			if f, ferr := normalizeTarFormat(rest); ferr == nil {
				return "tar", f, "", nil
			}
			switch rest {
			case "gzip", "bzip2", "lz4", "compress":
				return "tar", "gnu", rest, nil
			}
		case "cpio", "zip":
			return c, "", "", nil
		}
	}
	return "", "", "", fmt.Errorf("unknown format %q (want tar, cpio, zip, a tar variant, or tar+codec)", s)
}
