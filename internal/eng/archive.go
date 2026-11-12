/*
Copyright (C) Philip Schlump, 2012-2026.

BSD 3 Clause Licensed.
*/

// Package eng is the engine shared by every dialect: it peels
// compression layers by magic bytes, parses whichever container is
// found inside, and provides the extract/list/create/test/diff
// operations the CLI dialects map their flags onto.
package eng

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/pschlump/xtar/internal/cpiofmt"
	"github.com/pschlump/xtar/internal/layer"
	"github.com/pschlump/xtar/internal/member"
	"github.com/pschlump/xtar/internal/sniff"
	"github.com/pschlump/xtar/internal/tarfmt"
)

// maxPeel bounds the compression-layer onion so a crafted
// "gz(gz(gz(...)))" file is an error rather than a hang.
const maxPeel = 8

// Archive is a decoded archive held in memory (the whole-buffer model
// the pluto codecs currently impose; see the README).
type Archive struct {
	Path     string // as given; "" when read from stdin
	Stdin    bool
	Layers   []string // compression layers, outermost first
	Format   string   // "tar", "cpio", "zip", "bare"
	Variant  string   // tar: gnu/ustar/pax/v7; cpio: newc/crc/odc/binary; zip: ""/zip64
	Members  []member.Member
	Notes    []string // non-fatal observations worth a warning line
	Raw      []byte   // decoded container bytes
	Password string
	CompSize int64 // size of the outermost layer (the file on disk)
}

// UnsupportedError reports a recognized-but-unimplemented format.
func UnsupportedError(format string) error {
	return fmt.Errorf("%s archives are not supported yet — see the README section \"What is deliberately not supported\"", format)
}

// ErrNotArchive reports unrecognized content.
var ErrNotArchive = errors.New("this does not look like a recognized archive format")

// OpenFile reads and decodes path ("-" or "" means stdin).
func OpenFile(path, password string) (*Archive, error) {
	if path == "" || path == "-" {
		return OpenStdin(password)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	a, err := decode(data, password, path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return a, nil
}

// OpenStdin reads and decodes standard input.
func OpenStdin(password string) (*Archive, error) {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, err
	}
	a, err := decode(data, password, "")
	if err != nil {
		return nil, err
	}
	a.Stdin = true
	return a, nil
}

// Decode peels compression layers and parses the container inside.
func Decode(data []byte, password string) (*Archive, error) {
	return decode(data, password, "")
}

// decode is Decode with the file name the content came from, so a
// bare compressed stream can derive its implicit member name.
func decode(data []byte, password, name string) (*Archive, error) {
	a := &Archive{Password: password, Path: name}
	cur := data
	compSize := int64(len(data))
	for depth := 0; ; depth++ {
		if depth >= maxPeel {
			return nil, fmt.Errorf("more than %d nested compression layers", maxPeel)
		}
		r := sniff.Detect(cur)
		switch r.Kind {
		case sniff.Unsupported:
			return nil, UnsupportedError(r.Format)
		case sniff.Compression:
			dec, err := layer.Expand(r.Format, cur)
			if err != nil {
				return nil, fmt.Errorf("%s layer: %w", r.Format, err)
			}
			a.Layers = append(a.Layers, r.Format)
			compSize = int64(len(cur))
			cur = dec
			continue
		case sniff.Container:
			a.Raw = cur
			a.CompSize = compSize
			if err := parseContainer(a, r, cur); err != nil {
				return nil, err
			}
			return a, nil
		}
		// Unknown content.
		if len(a.Layers) > 0 {
			name := BareName(a.Path)
			if name == "" {
				return nil, errors.New("compressed stream does not contain an archive (and the file name carries no suffix to strip)")
			}
			a.Format = "bare"
			a.Variant = strings.Join(a.Layers, "→")
			a.Members = []member.Member{{
				Name:    name,
				Kind:    member.Regular,
				Mode:    0o644,
				ModTime: time.Now(),
				Data:    cur,
				Size:    int64(len(cur)),
			}}
			return a, nil
		}
		return nil, ErrNotArchive
	}
}

func parseContainer(a *Archive, r sniff.Result, cur []byte) error {
	switch r.Format {
	case "tar":
		t, err := tarfmt.Parse(cur)
		if err != nil {
			return fmt.Errorf("tar: %w", err)
		}
		a.Format = "tar"
		a.Variant = t.Variant
		a.Members = t.Members
		a.Notes = append(a.Notes, t.Notes...)
	case "cpio":
		c, err := cpiofmt.Parse(cur)
		if err != nil {
			return fmt.Errorf("%w", err)
		}
		a.Format = "cpio"
		a.Variant = c.Variant
		a.Members = c.Members
		a.Notes = append(a.Notes, c.Notes...)
	default:
		return UnsupportedError(r.Format)
	}
	return nil
}

// BareName strips compression and container suffixes from a file name
// so a bare compressed stream gets an implicit member name.  It
// returns "" when nothing could be stripped.
func BareName(orig string) string {
	if orig == "" {
		return ""
	}
	name := orig
	suffixes := []string{
		".gz", ".bz2", ".lz4", ".xz", ".zst", ".lzma",
		".Z", ".z",
		".tgz", ".taz", ".taZ", ".tbz", ".tbz2", ".tz2",
		".tar", ".cpio", ".zip",
	}
	stripped := false
	for {
		matched := ""
		for _, s := range suffixes {
			if strings.HasSuffix(name, s) && len(name) > len(s) {
				matched = s
				break
			}
		}
		if matched == "" {
			break
		}
		name = strings.TrimSuffix(name, matched)
		stripped = true
	}
	if !stripped {
		return ""
	}
	if i := strings.LastIndexAny(name, "/\\"); i >= 0 {
		name = name[i+1:]
	}
	return name
}

// SniffInfo is what --sniff reports.
type SniffInfo struct {
	Layers   []string
	Format   string
	Variant  string
	Members  int
	CompSize int64 // size of the outermost layer
	RawSize  int64 // size after peeling the compression layers
}

// SniffFile identifies an archive without extracting it.
func SniffFile(path string) (*SniffInfo, error) {
	a, err := OpenFile(path, "")
	if err != nil {
		return nil, err
	}
	return &SniffInfo{
		Layers:   a.Layers,
		Format:   a.Format,
		Variant:  a.Variant,
		Members:  len(a.Members),
		CompSize: a.CompSize,
		RawSize:  int64(len(a.Raw)),
	}, nil
}
