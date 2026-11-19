/*
Copyright (C) Philip Schlump, 2012-2026.

MIT Licensed.
*/

// Package arfmt reads the ar archive format (the Unix `ar` archive
// used for static libraries and Debian packages): a global magic, a
// sequence of 60-byte ASCII member headers with two-byte-aligned
// payloads, and the three name conventions in the wild — plain short
// names, BSD `#1/len` extended names (the name rides in the payload),
// and GNU long names through a `//` string table.
package arfmt

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/pschlump/xtar/internal/member"
)

const magic = "!<arch>\n"

// Archive is a parsed ar archive.
type Archive struct {
	Members []member.Member
	Notes   []string
}

// Parse decodes an ar archive.
func Parse(b []byte) (*Archive, error) {
	if len(b) < 8 || string(b[:8]) != magic {
		return nil, errors.New("ar: not an ar archive")
	}
	a := &Archive{}
	pos := 8
	longNames := "" // the GNU // string table
	for pos < len(b) {
		if len(b)-pos < 60 {
			return nil, fmt.Errorf("ar: truncated member header at offset %d", pos)
		}
		hdr := b[pos : pos+60]
		pos += 60
		if string(hdr[58:60]) != "`\n" {
			return nil, fmt.Errorf("ar: bad member header magic at offset %d", pos-60)
		}
		field := func(from, to int) string {
			return strings.TrimSpace(string(hdr[from:to]))
		}
		nameField := string(hdr[0:16]) // spaces are significant in BSD form
		size, err := strconv.Atoi(field(48, 58))
		if err != nil || size < 0 {
			return nil, fmt.Errorf("ar: bad member size at offset %d", pos-60)
		}
		if pos+size > len(b) {
			return nil, fmt.Errorf("ar: member %q is truncated", strings.TrimSpace(nameField))
		}
		data := b[pos : pos+size]
		pos += size
		if size%2 == 1 {
			if pos >= len(b) {
				return nil, errors.New("ar: missing alignment padding")
			}
			pos++ // members are two-byte aligned; the pad byte is `\n`
		}

		var name string
		var skip bool
		switch {
		case strings.HasPrefix(trimName(nameField), "#1/"):
			// BSD extended name: that many bytes of payload are the
			// name; the header size counts them.
			n, err := strconv.Atoi(strings.TrimSpace(trimName(nameField)[3:]))
			if err != nil || n < 0 || n > len(data) {
				return nil, fmt.Errorf("ar: bad BSD name length for %q", nameField)
			}
			name = strings.TrimRight(string(data[:n]), "\x00")
			data = data[n:]
			if strings.HasPrefix(name, "__.SYMDEF") {
				skip = true // the BSD symbol table
			}
		case trimName(nameField) == "/":
			skip = true // the GNU symbol table
		case trimName(nameField) == "//":
			// the GNU long-name string table
			longNames = string(data)
			skip = true
		case strings.HasPrefix(trimName(nameField), "/"):
			// GNU long name: the number is an offset into the table,
			// the name runs to a `/\n` or `\n` terminator
			off, err := strconv.Atoi(strings.TrimSpace(trimName(nameField)[1:]))
			if err != nil || off < 0 || off > len(longNames) {
				return nil, fmt.Errorf("ar: bad GNU name offset %q", nameField)
			}
			rest := longNames[off:]
			if i := strings.IndexByte(rest, '\n'); i >= 0 {
				rest = rest[:i]
			}
			name = strings.TrimSuffix(rest, "/")
		default:
			name = trimName(nameField)
			if strings.HasPrefix(name, "__.SYMDEF") {
				skip = true // the BSD symbol table, plain-name form
			}
		}
		if skip {
			continue
		}

		m := member.Member{
			Name:    name,
			Kind:    member.Regular,
			Mode:    0o644,
			ModTime: time.Unix(int64(parseOct(field(16, 28))), 0).UTC(),
			Data:    data,
			Size:    int64(len(data)),
		}
		if mode := parseOct(field(40, 48)); mode != 0 {
			m.Mode = uint32(mode & 0o7777)
		}
		a.Members = append(a.Members, m)
	}
	return a, nil
}

// trimName normalizes a raw name field: space- and NUL-padded both.
func trimName(s string) string {
	return strings.Trim(strings.Trim(s, "\x00"), " \t\r")
}

// parseOct reads an octal field, tolerating blanks (0 on garbage).
func parseOct(s string) int64 {
	v, err := strconv.ParseInt(s, 8, 64)
	if err != nil {
		return 0
	}
	return v
}
