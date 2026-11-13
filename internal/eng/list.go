/*
Copyright (C) Philip Schlump, 2012-2026.

BSD 3 Clause Licensed.
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
	for i := range a.Members {
		m := &a.Members[i]
		name, ok := selected(o, m.Name)
		if !ok {
			continue
		}
		if m.Kind == member.Directory {
			name += "/"
		}
		if o.Verbose >= 1 {
			link := ""
			if m.Kind == member.HardLink {
				link = " link to " + m.LinkName
			}
			fmt.Fprintf(o.Out, "%s %s %8d %s %s%s\n",
				m.ModeString(), ownerStr(m, o.Numeric), m.DataSize(),
				m.ModTime.Format("2006-01-02 15:04"), name, link)
		} else {
			fmt.Fprintln(o.Out, name)
		}
	}
}

func listCpio(a *Archive, o *ListOpts) {
	for i := range a.Members {
		m := &a.Members[i]
		name, ok := selected(o, m.Name)
		if !ok {
			continue
		}
		if o.Verbose >= 1 {
			fmt.Fprintf(o.Out, "%s %6d %s %s\n",
				m.ModeString(), m.DataSize(), m.ModTime.Format("Jan _2 15:04 2006"), name)
		} else {
			fmt.Fprintln(o.Out, name)
		}
	}
}

func listUnzip(a *Archive, o *ListOpts) {
	fmt.Fprintf(o.Out, "Archive:  %s\n", displayName(a))
	if o.Verbose >= 2 {
		fmt.Fprintf(o.Out, "  Length Method    Size Cmpr    Date    Time       CRC-32   Name\n")
		fmt.Fprintf(o.Out, "--------  ------ ------- ---- ---------- ----- ------------  ----\n")
	} else {
		fmt.Fprintf(o.Out, "  Length      Date    Time    Name\n")
		fmt.Fprintf(o.Out, "---------  ---------- -----   ----\n")
	}
	var total, nfiles, ndirs int
	for i := range a.Members {
		m := &a.Members[i]
		name, ok := selected(o, m.Name)
		if !ok {
			continue
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
			fmt.Fprintf(o.Out, "%8d %-8s %7d %3s%% %s %08x %s\n",
				m.DataSize(), zipMethodStr(m), zipCompSize(m), "-", m.ModTime.Format("2006-01-02 15:04"), zipCRC(m), name)
		} else {
			fmt.Fprintf(o.Out, "%9d  %s   %s\n", m.DataSize(), m.ModTime.Format("2006-01-02 15:04"), name)
		}
	}
	fmt.Fprintf(o.Out, "---------                     -------\n")
	fmt.Fprintf(o.Out, "%9d                     %d file%s, %d director%s\n",
		total, nfiles, plural(nfiles), ndirs, pluralY(ndirs))
}

func listZipinfo(a *Archive, o *ListOpts) {
	fmt.Fprintf(o.Out, "Archive:  %s\n", displayName(a))
	for i := range a.Members {
		m := &a.Members[i]
		name, ok := selected(o, m.Name)
		if !ok {
			continue
		}
		if m.Kind == member.Directory {
			name += "/"
		}
		fmt.Fprintf(o.Out, "%s  %s unx %8d %s %s\n",
			m.ModeString(), "1.0", m.DataSize(),
			m.ModTime.Format("20060102.150405"), name)
	}
}

func list7z(a *Archive, o *ListOpts) {
	fmt.Fprintf(o.Out, "\nListing archive: %s\n\n", displayName(a))
	fmt.Fprintf(o.Out, "--\nPath = %s\n", displayName(a))
	fmt.Fprintf(o.Out, "Type = %s\n", a.Format)
	fmt.Fprintf(o.Out, "Method = %s%s\n", strings.Join(a.Layers, ", "), containerMethod(a))
	fmt.Fprintf(o.Out, "\n   Date      Time    Attr         Size   Compressed  Name\n")
	fmt.Fprintf(o.Out, "------------------- ----- ------------ ------------  ------------------------\n")
	for i := range a.Members {
		m := &a.Members[i]
		name, ok := selected(o, m.Name)
		if !ok {
			continue
		}
		attr := "....A"
		switch m.Kind {
		case member.Directory:
			attr = "D...."
		case member.SymLink:
			attr = "....LA"
		}
		fmt.Fprintf(o.Out, "%s %s %12d %12s  %s\n",
			m.ModTime.Format("2006-01-02 15:04:05"), attr, m.DataSize(), "-", name)
	}
	fmt.Fprintf(o.Out, "------------------- ----- ------------ ------------  ------------------------\n")
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
			fmt.Fprintf(out, "Archive:  %s\n", displayName(a))
		}
		for i := range a.Members {
			m := &a.Members[i]
			name := m.Name
			if m.Kind == member.Directory {
				name += "/"
			}
			if m.Raw != nil && m.Raw.CRC != zipCRC32(m.Data) {
				bad++
				fmt.Fprintf(out, "    testing: %-42s bad CRC %08x (want %08x)\n", name, zipCRC32(m.Data), m.Raw.CRC)
			} else if verbose {
				fmt.Fprintf(out, "    testing: %-42s OK\n", name)
			}
		}
		if verbose {
			fmt.Fprintf(out, "No errors detected in %s\n", displayName(a))
		}
		if bad > 0 {
			return fmt.Errorf("%d member(s) failed the CRC check", bad)
		}
		return nil
	}
	if verbose {
		fmt.Fprintf(out, "%s: structure and checksums verified (container %s)\n", displayName(a), a.Format)
	}
	return nil
}

// Diff compares archive members against the filesystem under dir
// (tar -d) and returns the number of differences.
func Diff(a *Archive, dir string, out io.Writer, warn func(string)) int {
	diffs := 0
	for i := range a.Members {
		m := &a.Members[i]
		fsPath := filepath.Join(dir, filepath.FromSlash(m.Name))
		fi, err := os.Lstat(fsPath)
		name := m.Name
		if m.Kind == member.Directory {
			name += "/"
		}
		if err != nil {
			fmt.Fprintf(out, "%s: does not exist\n", name)
			diffs++
			continue
		}
		switch m.Kind {
		case member.Regular:
			if !fi.Mode().IsRegular() {
				fmt.Fprintf(out, "%s: type differs\n", name)
				diffs++
				continue
			}
			data, err := os.ReadFile(fsPath)
			if err != nil {
				fmt.Fprintf(out, "%s: cannot read: %v\n", name, err)
				diffs++
				continue
			}
			if len(data) != len(m.Data) {
				fmt.Fprintf(out, "%s: size differs\n", name)
				diffs++
				continue
			}
			for j := range data {
				if data[j] != m.Data[j] {
					fmt.Fprintf(out, "%s: contents differ\n", name)
					diffs++
					break
				}
			}
		case member.SymLink:
			target, _ := os.Readlink(fsPath)
			if target != m.LinkName {
				fmt.Fprintf(out, "%s: link target differs\n", name)
				diffs++
			}
		}
		if !fi.ModTime().Truncate(1e9).Equal(m.ModTime.Truncate(1e9)) && fi.ModTime().Unix() != m.ModTime.Unix() {
			fmt.Fprintf(out, "%s: mod time differs\n", name)
			diffs++
		}
	}
	return diffs
}
