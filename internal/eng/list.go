/*
Copyright (C) Philip Schlump, 2012-2026.

MIT Licensed.
*/

package eng

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/pschlump/pluto/crc"
	"github.com/pschlump/xtar/internal/member"
	"github.com/pschlump/xtar/internal/pat"
)

// zipTable is the zip/gzip CRC-32 polynomial table (IEEE, 0xEDB88320).
var zipTable = crc.MakeTable32(0xEDB88320)

// zipCRC32 is the CRC-32 used by zip and gzip.
func zipCRC32(data []byte) uint32 { return crc.Checksum32(data, zipTable) }

// ListOpts controls listing output.
type ListOpts struct {
	Out     io.Writer
	Verbose int
	Numeric bool   // numeric uid/gid in listings
	Style   string // "tar", "cpio", "unzip", "zipinfo", "7z", "xtar"
	Include []*pat.Pattern
	Exclude []*pat.Pattern
	Strip   int
	Warn    func(string) // notes discovered while streaming (truncated tail, …)
}

// List prints the member table in the dialect's style.
func List(a *Archive, o *ListOpts) {
	switch o.Style {
	case "unzip":
		listUnzip(a, o)
	case "zipinfo":
		listZipinfo(a, o)
	case "7z":
		list7z(a, o)
	case "cpio":
		listCpio(a, o)
	default: // "tar", "xtar"
		listTar(a, o)
	}
}

func selected(o *ListOpts, name string) (string, bool) {
	if !pat.IncludeMatch(o.Include, name) || pat.ExcludeMatch(o.Exclude, name) {
		return "", false
	}
	if o.Strip > 0 {
		parts := strings.Split(name, "/")
		if len(parts) <= o.Strip {
			return "", false
		}
		name = strings.Join(parts[o.Strip:], "/")
	}
	return name, true
}

func ownerStr(m *member.Member, numeric bool) string {
	u, g := fmt.Sprint(m.UID), fmt.Sprint(m.GID)
	if !numeric {
		if m.Uname != "" {
			u = m.Uname
		}
		if m.Gname != "" {
			g = m.Gname
		}
	}
	return u + "/" + g
}

func listTar(a *Archive, o *ListOpts) {
	n0 := len(a.Notes)
	_ = a.Each(func(m *member.Member, _ io.Reader) error {
		name, ok := selected(o, m.Name)
		if !ok {
			return nil
		}
		if m.Kind == member.Directory {
			name += "/"
		}
		if o.Verbose >= 1 {
			link := ""
			if m.Kind == member.HardLink {
				link = " link to " + m.LinkName
			}
			outf(o.Out, "%s %s %8d %s %s%s\n",
				m.ModeString(), ownerStr(m, o.Numeric), m.DataSize(),
				m.ModTime.Format("2006-01-02 15:04"), name, link)
		} else {
			outf(o.Out, "%s\n", name)
		}
		return nil
	})
	flushNotes(a, o.Warn, n0)
}

func listCpio(a *Archive, o *ListOpts) {
	n0 := len(a.Notes)
	_ = a.Each(func(m *member.Member, _ io.Reader) error {
		name, ok := selected(o, m.Name)
		if !ok {
			return nil
		}
		if o.Verbose >= 1 {
			outf(o.Out, "%s %6d %s %s\n",
				m.ModeString(), m.DataSize(), m.ModTime.Format("Jan _2 15:04 2006"), name)
		} else {
			outf(o.Out, "%s\n", name)
		}
		return nil
	})
	flushNotes(a, o.Warn, n0)
}

// outf writes one listing line.  A failing output writer (a closed
// stdout mid-listing) leaves nothing useful to do, so the error is
// dropped — the native tools' listings behave the same way.
func outf(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}

func listUnzip(a *Archive, o *ListOpts) {
	outf(o.Out, "Archive:  %s\n", displayName(a))
	if o.Verbose >= 2 {
		outf(o.Out, "  Length Method    Size Cmpr    Date    Time       CRC-32   Name\n")
		outf(o.Out, "--------  ------ ------- ---- ---------- ----- ------------  ----\n")
	} else {
		outf(o.Out, "  Length      Date    Time    Name\n")
		outf(o.Out, "---------  ---------- -----   ----\n")
	}
	var total, nfiles, ndirs int
	_ = a.Each(func(m *member.Member, _ io.Reader) error {
		name, ok := selected(o, m.Name)
		if !ok {
			return nil
		}
		isDir := m.Kind == member.Directory
		if isDir {
			name += "/"
			ndirs++
		} else {
			nfiles++
		}
		total += int(m.DataSize())
		if o.Verbose >= 2 {
			outf(o.Out, "%8d %-8s %7d %3s%% %s %08x %s\n",
				m.DataSize(), zipMethodStr(m), zipCompSize(m), "-", m.ModTime.Format("2006-01-02 15:04"), zipCRC(m), name)
		} else {
			outf(o.Out, "%9d  %s   %s\n", m.DataSize(), m.ModTime.Format("2006-01-02 15:04"), name)
		}
		return nil
	})
	outf(o.Out, "---------                     -------\n")
	outf(o.Out, "%9d                     %d file%s, %d director%s\n",
		total, nfiles, plural(nfiles), ndirs, pluralY(ndirs))
}

func listZipinfo(a *Archive, o *ListOpts) {
	outf(o.Out, "Archive:  %s\n", displayName(a))
	_ = a.Each(func(m *member.Member, _ io.Reader) error {
		name, ok := selected(o, m.Name)
		if !ok {
			return nil
		}
		if m.Kind == member.Directory {
			name += "/"
		}
		outf(o.Out, "%s  %s unx %8d %s %s\n",
			m.ModeString(), "1.0", m.DataSize(),
			m.ModTime.Format("20060102.150405"), name)
		return nil
	})
}

func list7z(a *Archive, o *ListOpts) {
	outf(o.Out, "\nListing archive: %s\n\n", displayName(a))
	outf(o.Out, "--\nPath = %s\n", displayName(a))
	outf(o.Out, "Type = %s\n", a.Format)
	outf(o.Out, "Method = %s%s\n", strings.Join(a.Layers, ", "), containerMethod(a))
	outf(o.Out, "\n   Date      Time    Attr         Size   Compressed  Name\n")
	outf(o.Out, "------------------- ----- ------------ ------------  ------------------------\n")
	_ = a.Each(func(m *member.Member, _ io.Reader) error {
		name, ok := selected(o, m.Name)
		if !ok {
			return nil
		}
		attr := "....A"
		switch m.Kind {
		case member.Directory:
			attr = "D...."
		case member.SymLink:
			attr = "....LA"
		}
		outf(o.Out, "%s %s %12d %12s  %s\n",
			m.ModTime.Format("2006-01-02 15:04:05"), attr, m.DataSize(), "-", name)
		return nil
	})
	outf(o.Out, "------------------- ----- ------------ ------------  ------------------------\n")
}

func displayName(a *Archive) string {
	if a.Path == "" {
		return "(stdin)"
	}
	return a.Path
}

func containerMethod(a *Archive) string {
	switch a.Format {
	case "tar":
		if len(a.Layers) == 0 {
			return "Copy"
		}
		return ""
	case "zip":
		return "Deflate"
	}
	return ""
}

func zipMethodStr(m *member.Member) string {
	if m.Raw != nil {
		switch m.Raw.Method {
		case 0:
			return "Stored"
		case 8:
			return "Defl:Ns"
		case 12:
			return "BZip2"
		default:
			return fmt.Sprintf("Method%d", m.Raw.Method)
		}
	}
	switch m.Method {
	case 0:
		return "Stored"
	case 12:
		return "BZip2"
	default:
		return "Defl:Ns"
	}
}

func zipCompSize(m *member.Member) int64 {
	if m.Raw != nil {
		return int64(m.Raw.CompSize)
	}
	return 0
}

func zipCRC(m *member.Member) uint32 {
	if m.Raw != nil {
		return m.Raw.CRC
	}
	return 0
}

func plural(n int) string  { return map[bool]string{true: "s", false: ""}[n != 1] }
func pluralY(n int) string { return map[bool]string{true: "ies", false: "y"}[n != 1] }

// Test verifies member checksums where the container carries them and
// reports in the unzip -t shape.  tar/cpio/bare streams were already
// structurally validated during Decode (gzip/bzip2/lz4 checksums live
// in their trailers).
func Test(a *Archive, out io.Writer, verbose bool) error {
	bad := 0
	if a.Format == "zip" {
		if verbose {
			outf(out, "Archive:  %s\n", displayName(a))
		}
		for i := range a.Members {
			m := &a.Members[i]
			name := m.Name
			if m.Kind == member.Directory {
				name += "/"
			}
			if m.Raw != nil && m.Raw.CRC != zipCRC32(m.Data) {
				bad++
				outf(out, "    testing: %-42s bad CRC %08x (want %08x)\n", name, zipCRC32(m.Data), m.Raw.CRC)
			} else if verbose {
				outf(out, "    testing: %-42s OK\n", name)
			}
		}
		if verbose {
			outf(out, "No errors detected in %s\n", displayName(a))
		}
		if bad > 0 {
			return fmt.Errorf("%d member(s) failed the CRC check", bad)
		}
		return nil
	}
	if verbose {
		outf(out, "%s: structure and checksums verified (container %s)\n", displayName(a), a.Format)
	}
	return nil
}

// Diff compares archive members against the filesystem under dir
// (tar -d) and returns the number of differences.  Member content
// streams, compared in chunks.
func Diff(a *Archive, dir string, out io.Writer, warn func(string)) int {
	n0 := len(a.Notes)
	diffs := 0
	_ = a.Each(func(m *member.Member, data io.Reader) error {
		fsPath := filepath.Join(dir, filepath.FromSlash(m.Name))
		fi, err := os.Lstat(fsPath)
		name := m.Name
		if m.Kind == member.Directory {
			name += "/"
		}
		if err != nil {
			outf(out, "%s: does not exist\n", name)
			diffs++
			return nil
		}
		switch m.Kind {
		case member.Regular:
			if !fi.Mode().IsRegular() {
				outf(out, "%s: type differs\n", name)
				diffs++
				return nil
			}
			if fi.Size() != m.DataSize() {
				outf(out, "%s: size differs\n", name)
				diffs++
				return nil
			}
			var same bool
			if m.Sparse != nil {
				same = sameSparseContent(fsPath, data, m.Sparse)
			} else {
				same = sameContent(fsPath, data)
			}
			if !same {
				outf(out, "%s: contents differ\n", name)
				diffs++
			}
		case member.SymLink:
			target, _ := os.Readlink(fsPath)
			if target != m.LinkName {
				outf(out, "%s: link target differs\n", name)
				diffs++
			}
		case member.HardLink:
			// GNU tar -d: the file must still share its inode with the
			// link target (a copy breaks the link).
			tfi, terr := os.Lstat(filepath.Join(dir, filepath.FromSlash(m.LinkName)))
			if terr != nil || !os.SameFile(fi, tfi) {
				outf(out, "%s: not linked to %s\n", name, m.LinkName)
				diffs++
			}
		}
		if !fi.ModTime().Truncate(1e9).Equal(m.ModTime.Truncate(1e9)) && fi.ModTime().Unix() != m.ModTime.Unix() {
			outf(out, "%s: mod time differs\n", name)
			diffs++
		}
		return nil
	})
	flushNotes(a, warn, n0)
	return diffs
}

// sameContent compares a file against a member's data stream in
// chunks.  A short or unreadable member stream counts as a
// difference.
func sameContent(fsPath string, data io.Reader) bool {
	f, err := os.Open(fsPath)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	var ab, bb [64 * 1024]byte
	for {
		an, aerr := io.ReadFull(data, ab[:])
		bn, berr := io.ReadFull(f, bb[:])
		if !bytesEqual(ab[:an], bb[:bn]) {
			return false
		}
		switch {
		case aerr == nil && berr == nil:
			continue
		case aerr == io.EOF && berr == io.EOF, aerr == io.ErrUnexpectedEOF && berr == io.ErrUnexpectedEOF:
			return an == bn
		default:
			// one side ended before the other, or a read failed
			return false
		}
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// sameSparseContent compares a sparse member's extents, each at its
// offset in the file, against the member's tight data stream.
func sameSparseContent(fsPath string, data io.Reader, spans []member.SparseSpan) bool {
	f, err := os.Open(fsPath)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	var fb, db [32 * 1024]byte
	for _, sp := range spans {
		for left := sp.Len; left > 0; {
			n := int64(len(fb))
			if left < n {
				n = left
			}
			if _, err := f.ReadAt(fb[:n], sp.Off+(sp.Len-left)); err != nil {
				return false
			}
			if _, err := io.ReadFull(data, db[:n]); err != nil {
				return false
			}
			if !bytesEqual(fb[:n], db[:n]) {
				return false
			}
			left -= n
		}
	}
	return true
}
