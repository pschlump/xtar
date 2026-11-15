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
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/pschlump/xtar/internal/charset"
	"github.com/pschlump/xtar/internal/cpiofmt"
	"github.com/pschlump/xtar/internal/layer"
	"github.com/pschlump/xtar/internal/member"
	"github.com/pschlump/xtar/internal/sevenzfmt"
	"github.com/pschlump/xtar/internal/sniff"
	"github.com/pschlump/xtar/internal/tarfmt"
	"github.com/pschlump/xtar/internal/zipfmt"
)

// maxPeel bounds the compression-layer onion so a crafted
// "gz(gz(gz(...)))" file is an error rather than a hang.
const maxPeel = 8

// Archive is a decoded archive.  Zip and bare archives (and anything
// opened through Decode) hold every member and its data in memory;
// tar and cpio archives opened from a stream carry their members as
// Each walks them, so memory is bounded by the largest member rather
// than the archive.  Which mode an Archive is in is an internal
// detail: every consumer iterates through Each the same way.
type Archive struct {
	Path     string // as given; "" when read from stdin
	Stdin    bool
	Layers   []string // compression layers, outermost first
	Format   string   // "tar", "cpio", "zip", "bare"
	Variant  string   // tar: gnu/ustar/pax/v7; cpio: newc/crc/odc/binary; zip: ""/zip64
	Members  []member.Member
	Notes    []string // non-fatal observations worth a warning line
	Raw      []byte   // decoded container bytes (whole-buffer mode only)
	Comment  string   // zip archive comment
	Password string
	CompSize int64 // size of the outermost layer (the file on disk)

	// src is non-nil while members stream through Each (data is not
	// buffered); Close releases it.
	src *streamState

	// dec, set by SetEncoding, reinterprets member names stored
	// without a declared character set.
	dec charset.Decoder
}

// SetEncoding reinterprets member names as enc ("cp437",
// "iso-8859-1", "mac-roman", "utf-8") — the zips old Windows and
// classic-Mac tools wrote, and tar/cpio names that carry no charset
// of their own.  Names already declared UTF-8 (a zip's EFS bit, pax
// records) are left alone.  It applies to the members already loaded
// and to the ones Each walks later.
func (a *Archive) SetEncoding(enc string) error {
	if enc == "" {
		return nil
	}
	dec, err := charset.ByName(enc)
	if err != nil {
		return err
	}
	a.dec = dec
	for i := range a.Members {
		a.recode(&a.Members[i])
	}
	return nil
}

// recode rewrites one member's name (and link target) through the
// archive's encoding, from the stored bytes where the container kept
// them.
func (a *Archive) recode(m *member.Member) {
	if a.dec == nil {
		return
	}
	if m.Raw != nil {
		if m.Raw.Flags&0x800 != 0 {
			return // the EFS bit declares UTF-8
		}
		if m.Raw.RawName != nil {
			m.Name = a.dec(m.Raw.RawName)
		}
	} else {
		m.Name = a.dec([]byte(m.Name))
	}
	if m.LinkName != "" {
		m.LinkName = a.dec([]byte(m.LinkName))
	}
}

// streamState is the streaming read side of an Archive: the codec
// chain from layer.Open plus whichever container reader walks it.
type streamState struct {
	rc      io.ReadCloser
	closer  io.Closer // the file the stream came from, when there is one
	tr      *tarfmt.Reader
	cr      *cpiofmt.Reader
	notesIn int  // reader notes already merged into a.Notes
	done    bool // one walk per stream: reopen instead of iterating twice
}

func (s *streamState) next() (*member.Member, error) {
	if s.tr != nil {
		return s.tr.Next()
	}
	return s.cr.Next()
}

// Read streams the current member's data through the container
// reader, so Each can hand streamState itself out as the data reader.
func (s *streamState) Read(p []byte) (int, error) {
	if s.tr != nil {
		return s.tr.Read(p)
	}
	return s.cr.Read(p)
}

// takeNotes returns the container reader's notes not yet merged and
// marks them taken.
func (s *streamState) takeNotes() []string {
	var all []string
	if s.tr != nil {
		all = s.tr.Notes()
	} else {
		all = s.cr.Notes()
	}
	fresh := all[s.notesIn:]
	s.notesIn = len(all)
	return fresh
}

// settle finalizes variant and notes from the container reader once
// iteration ends.
func (s *streamState) settle(a *Archive) {
	if s.tr != nil {
		a.Variant = s.tr.Variant()
		if s.tr.PAXSeen() {
			a.Variant += "+pax"
		}
	} else {
		a.Variant = s.cr.Variant()
	}
	a.Notes = append(a.Notes, s.takeNotes()...)
}

// Close releases the archive's streaming resources: the codec chain
// and, for OpenFile, the underlying file.  Whole-buffer archives are a
// no-op.  The archive cannot be iterated again after Close.
func (a *Archive) Close() error {
	if a.src == nil {
		return nil
	}
	s := a.src
	a.src = nil
	err := s.rc.Close()
	if s.closer != nil {
		if e := s.closer.Close(); err == nil {
			err = e
		}
	}
	return err
}

// Each visits every member in archive order.  For a member that
// carries content (a regular file), data streams its bytes; for every
// other kind it is an empty reader (a symlink's target is m.LinkName).
// data is valid only inside visit; whatever it does not read is
// discarded.  Members accumulate in a.Members as the walk proceeds
// (metadata only in streaming mode), and container notes surface in
// a.Notes as they are discovered.  A streaming archive can be walked
// once.
func (a *Archive) Each(visit func(m *member.Member, data io.Reader) error) error {
	if a.src == nil {
		for i := range a.Members {
			m := &a.Members[i]
			var data io.Reader = emptyReader{}
			if len(m.Data) > 0 {
				data = bytes.NewReader(m.Data)
			}
			if err := visit(m, data); err != nil {
				return err
			}
		}
		return nil
	}
	s := a.src
	if s.done {
		return fmt.Errorf("archive already streamed: reopen it to walk it again")
	}
	s.done = true
	err := func() error {
		for {
			m, err := s.next()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			a.recode(m)                       // --encoding applies as members walk by
			a.Members = append(a.Members, *m) // the metadata trail; data streams
			var data io.Reader = emptyReader{}
			switch {
			case m.Kind == member.Regular:
				data = s // the Reader itself serves the current member
			case len(m.Data) > 0:
				data = bytes.NewReader(m.Data)
			}
			if err := visit(m, data); err != nil {
				return err
			}
		}
	}()
	s.settle(a)
	return err
}

// flushNotes prints the notes added to a since mark through warn.
func flushNotes(a *Archive, warn func(string), mark int) {
	if warn == nil {
		return
	}
	for _, n := range a.Notes[mark:] {
		warn(n)
	}
}

type emptyReader struct{}

func (emptyReader) Read([]byte) (int, error) { return 0, io.EOF }

// UnsupportedError reports a recognized-but-unimplemented format.
func UnsupportedError(format string) error {
	return fmt.Errorf("%s archives are not supported yet — see the README section \"What is deliberately not supported\"", format)
}

// ErrNotArchive reports unrecognized content.
var ErrNotArchive = errors.New("this does not look like a recognized archive format")

// OpenFile reads and opens the archive at path ("-" or "" means
// stdin).  Tar and cpio containers stream; zip and bare content is
// loaded whole.  A split zip set (name.z01… beside name.zip) is
// assembled from its parts.  The caller must Close the archive when
// done.
func OpenFile(path, password string) (*Archive, error) {
	if path == "" || path == "-" {
		return OpenStdin(password)
	}
	if parts, ok := splitSet(path); ok {
		return openSplitZip(path, parts, password)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	a, err := OpenStream(f, path, password)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if fi, err := f.Stat(); err == nil {
		a.CompSize = fi.Size()
	}
	if a.src != nil {
		a.src.closer = f // Close releases the codec chain and the file
	} else {
		_ = f.Close()
	}
	return a, nil
}

// OpenStdin reads and opens the archive on standard input (streaming
// for tar and cpio; the compressed size is unknown on a pipe).
func OpenStdin(password string) (*Archive, error) {
	a, err := OpenStream(os.Stdin, "", password)
	if err != nil {
		return nil, err
	}
	a.Stdin = true
	return a, nil
}

// OpenStream peels the compression layers off r and opens the
// container inside: tar and cpio stream member by member (iterate
// with Each); zip and bare content is decoded whole, because the zip
// central directory sits at the end and a bare stream is a single
// member.  OpenStream never closes r.
func OpenStream(r io.Reader, name, password string) (*Archive, error) {
	rc, codecs, res, err := layer.Open(r)
	if err != nil {
		return nil, err
	}
	a := &Archive{Password: password, Path: name, Layers: codecs}
	switch res.Kind {
	case sniff.Unsupported:
		_ = rc.Close()
		return nil, UnsupportedError(res.Format)
	case sniff.Container:
		switch res.Format {
		case "tar":
			a.Format = "tar"
			a.Variant = res.Variant
			a.src = &streamState{rc: rc, tr: tarfmt.NewReader(rc)}
			return a, nil
		case "cpio":
			a.Format = "cpio"
			a.Variant = res.Variant
			a.src = &streamState{rc: rc, cr: cpiofmt.NewReader(rc)}
			return a, nil
		}
		// zip: the central directory is at the end — read it whole.
		body, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			return nil, err
		}
		a.Raw = body
		if err := parseContainer(a, res, body); err != nil {
			return nil, err
		}
		return a, nil
	case sniff.Compression:
		// layer.Open never returns Compression; unreachable.
		_ = rc.Close()
		return nil, fmt.Errorf("internal: peel returned a compression layer")
	}
	// Unknown content: a bare compressed stream is one member named
	// after the file; anything else is not an archive we know.
	if len(codecs) > 0 {
		body, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			return nil, err
		}
		base := BareName(name)
		if base == "" {
			return nil, errors.New("compressed stream does not contain an archive (and the file name carries no suffix to strip)")
		}
		a.Format = "bare"
		a.Variant = strings.Join(codecs, "→")
		a.Raw = body
		a.Members = []member.Member{{
			Name:    base,
			Kind:    member.Regular,
			Mode:    0o644,
			ModTime: time.Now(),
			Data:    body,
			Size:    int64(len(body)),
		}}
		return a, nil
	}
	_ = rc.Close()
	return nil, ErrNotArchive
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
	case "zip":
		z, err := zipfmt.Parse(cur, a.Password)
		if err != nil {
			return fmt.Errorf("%w", err)
		}
		a.Format = "zip"
		a.Variant = z.Variant
		a.Members = z.Members
		a.Comment = z.Comment
		a.Notes = append(a.Notes, z.Notes...)
	case "7z":
		sz, err := sevenzfmt.Parse(cur, a.Password)
		if err != nil {
			return fmt.Errorf("%w", err)
		}
		a.Format = "7z"
		a.Members = sz.Members
		a.Notes = append(a.Notes, sz.Notes...)
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

// SniffFile identifies an archive without extracting it.  It reads
// the whole file (it reports sizes, so there is nothing to save by
// streaming); a split zip set is assembled from its parts first.
func SniffFile(path string) (*SniffInfo, error) {
	if parts, ok := splitSet(path); ok {
		a, err := openSplitZip(path, parts, "")
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
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	a, err := decode(data, "", path)
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
