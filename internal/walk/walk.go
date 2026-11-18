/*
Copyright (C) Philip Schlump, 2012-2026.

MIT Licensed.
*/

// Package walk turns a list of filesystem operands into archive
// members, applying include/exclude patterns, recursion rules and
// symlink policy.
package walk

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"strings"

	"github.com/pschlump/xtar/internal/member"
	"github.com/pschlump/xtar/internal/pat"
)

// NamePolicy selects how operand names become member names.  The
// policies differ on a leading "./" (kept verbatim by GNU tar, bsdtar
// and cpio; stripped by Info-ZIP), on a "." root operand (stored as a
// member by tar; dropped by zip), and on a leading ".." (stripped with
// a notice by GNU tar; kept by cpio).
type NamePolicy int

const (
	// ZipNames is the Info-ZIP policy: strip leading "./" prefixes and
	// store no "." root member.
	ZipNames NamePolicy = iota
	// TarNames is the GNU tar/bsdtar policy: keep names as typed
	// relative to their base ("./f.txt", a "." root member) and strip
	// leading ".." components with a notice.
	TarNames
	// CpioNames keeps every name as given ("./x", "../x"), stripping
	// only a leading "/".
	CpioNames
)

// Opts controls member gathering.
type Opts struct {
	Files []string
	// Names holds the archive-name base for each Files entry: the
	// operand as the user typed it, relative to its -C directory, while
	// Files carries the filesystem path the walk reads.  A missing
	// (nil or shorter) entry defaults to the path itself.
	Names []string
	// NamePolicy is the dialect's member-naming policy; ZipNames (the
	// default) keeps the historical xtar behavior.
	NamePolicy NamePolicy

	StdinList bool // read the file list from stdin instead
	NullSep   bool // stdin list is NUL-separated

	Recurse     bool // walk into directory operands (tar/7z default, zip needs -r)
	NoRecursion bool // --no-recursion: store directory operands as bare entries
	OneFS       bool // -l: do not cross device boundaries
	Follow      bool // -h: dereference symlinks
	Symlinks    bool // store symlinks as symlink members (tar/cpio default; zip needs -y)
	Junk        bool // -j: store base names only
	NoDirs      bool // -D: do not store directory entries at all
	Sparse      bool // -S: store holes as sparse extents instead of zeros

	Exclude []*pat.Pattern
	Include []*pat.Pattern

	Owner, Group int
	HaveOwner    bool
	HaveGroup    bool
	NumericOwner bool
	Transform    func(string) string
	Warn         func(string)
	Notice       func(string) // informational lines that are not warnings (leading-'/' strip)
	OnName       func(string)
}

type gatherer struct {
	o                 *Opts
	out               *[]member.Member
	seen              map[string]bool
	links             map[[2]uint64]string // (dev, ino) -> first member name
	users             map[int]string
	groups            map[int]string
	rootDev           uint64
	haveRootDev       bool
	warnedAbs         bool
	warnedDotDot      bool
	warnedDotDotSlash bool
}

// Gather walks the operands and returns the members to store.
func Gather(o *Opts) ([]member.Member, error) {
	names := o.Files
	if o.StdinList {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, err
		}
		sep := byte('\n')
		if o.NullSep {
			sep = 0
		}
		names = nil
		for _, f := range bytes.Split(data, []byte{sep}) {
			s := strings.TrimRight(string(f), "\r")
			if s != "" {
				names = append(names, s)
			}
		}
	}
	var out []member.Member
	g := &gatherer{
		o:      o,
		out:    &out,
		seen:   map[string]bool{},
		links:  map[[2]uint64]string{},
		users:  map[int]string{},
		groups: map[int]string{},
	}
	for i, name := range names {
		base := name
		if i < len(o.Names) && o.Names[i] != "" {
			base = o.Names[i]
		}
		g.addRoot(name, base)
	}
	return out, nil
}

func (g *gatherer) warnf(format string, args ...any) {
	if g.o.Warn != nil {
		g.o.Warn(fmt.Sprintf(format, args...))
	}
}

func (g *gatherer) noticef(format string, args ...any) {
	if g.o.Notice != nil {
		g.o.Notice(fmt.Sprintf(format, args...))
	}
}

// slash cleans an operand path into an archive member name according
// to the dialect's NamePolicy.  Every policy strips a leading "/"
// with a one-time notice, the way GNU tar does.
func (g *gatherer) slash(p string) string {
	name := filepath.ToSlash(p)
	switch g.o.NamePolicy {
	case ZipNames:
		for strings.HasPrefix(name, "./") {
			name = name[2:]
		}
		if name == "." { // Info-ZIP stores no "." root entry
			return ""
		}
	case TarNames:
		for strings.HasPrefix(name, "../") {
			if !g.warnedDotDotSlash {
				g.warnedDotDotSlash = true
				g.noticef("Removing leading `../' from member names")
			}
			name = name[3:]
		}
		if name == ".." {
			if !g.warnedDotDot {
				g.warnedDotDot = true
				g.noticef("Removing leading `..' from member names")
			}
			name = "."
		}
	}
	if strings.HasPrefix(name, "/") {
		name = strings.TrimPrefix(name, "/")
		if !g.warnedAbs {
			g.warnedAbs = true
			g.noticef("Removing leading `/' from member names")
		}
	}
	return name
}

// addRoot walks the filesystem path fsPath, naming members from base
// (the operand as typed): the root itself is base, and each entry
// below it is base plus its path relative to the root — so "-C d ."
// reads d/ but stores "." and "./f.txt", matching GNU tar.
func (g *gatherer) addRoot(fsPath, base string) {
	fi, err := os.Lstat(fsPath)
	if err != nil {
		g.warnf("%s: cannot stat: %v", fsPath, err)
		return
	}
	if fi.IsDir() && g.o.Recurse && !g.o.NoRecursion {
		g.rootDev, g.haveRootDev = statDev(fi)
		err := filepath.WalkDir(fsPath, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				g.warnf("%s: %v", p, err)
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			name := base
			if p != fsPath {
				rel, rerr := filepath.Rel(fsPath, p)
				if rerr != nil {
					return nil // cannot happen inside our own walk
				}
				name = base + "/" + filepath.ToSlash(rel)
			}
			name = g.slash(name)
			if name == "" {
				return nil
			}
			if pat.ExcludeMatch(g.o.Exclude, name) {
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if !d.IsDir() && len(g.o.Include) > 0 && !pat.IncludeMatch(g.o.Include, name) {
				return nil
			}
			if g.o.OneFS && d.IsDir() && g.haveRootDev {
				if fi, err := d.Info(); err == nil {
					if dev, ok := statDev(fi); ok && dev != g.rootDev {
						return fs.SkipDir
					}
				}
			}
			fi, err := d.Info()
			if err != nil {
				g.warnf("%s: %v", p, err)
				return nil
			}
			g.addEntry(name, p, fi)
			return nil
		})
		if err != nil {
			g.warnf("%s: walk: %v", fsPath, err)
		}
		return
	}
	g.addEntry(g.slash(base), fsPath, fi)
}

func (g *gatherer) addEntry(name, fsPath string, fi os.FileInfo) {
	if g.o.NoDirs && fi.IsDir() {
		return
	}
	if g.o.Follow && fi.Mode()&os.ModeSymlink != 0 {
		st, err := os.Stat(fsPath)
		if err != nil {
			g.warnf("%s: cannot dereference: %v", fsPath, err)
			return
		}
		fi = st
	}

	m := member.Member{ModTime: fi.ModTime()}
	m.UID, m.GID = statOwner(fi)

	var linkKey *[2]uint64 // set when this member anchors a link family

	switch {
	case fi.IsDir():
		m.Kind = member.Directory
		m.Mode = member.FromFileMode(fi.Mode())
	case fi.Mode()&os.ModeSymlink != 0 && g.o.Symlinks:
		m.Kind = member.SymLink
		m.Mode = 0o777
		target, err := os.Readlink(fsPath)
		if err != nil {
			g.warnf("%s: readlink: %v", fsPath, err)
			return
		}
		m.LinkName = filepath.ToSlash(target)
		m.Data = []byte(m.LinkName)
		m.Size = int64(len(m.Data))
	case fi.Mode()&os.ModeNamedPipe != 0:
		m.Kind = member.FIFO
		m.Mode = member.FromFileMode(fi.Mode())
	case fi.Mode().IsRegular():
		// A second (or later) name for an inode already stored becomes
		// a hard-link member pointing at the first, the way tar/cpio
		// store link families.
		if dev, ino, ok := statID(fi); ok {
			m.Dev, m.Ino = dev, ino
			if nlink, ok2 := statNLink(fi); ok2 {
				m.NLink = nlink
			}
			if first, seen := g.links[[2]uint64{dev, ino}]; seen {
				m.Kind = member.HardLink
				m.Mode = member.FromFileMode(fi.Mode())
				m.LinkName = first
				break
			}
			linkKey = &[2]uint64{dev, ino}
		}
		m.Kind = member.Regular
		m.Mode = member.FromFileMode(fi.Mode())
		var data []byte
		var err error
		if g.o.Sparse {
			data, m.Sparse, err = readSparse(fsPath, fi.Size())
		} else {
			data, err = os.ReadFile(fsPath)
		}
		if err != nil {
			g.warnf("%s: cannot read: %v", fsPath, err)
			return
		}
		m.Data = data
		m.Size = fi.Size()
		if m.Sparse == nil {
			m.Size = int64(len(data))
		}
	default:
		g.warnf("%s: unsupported file type %v, skipping", fsPath, fi.Mode().Type())
		return
	}

	if g.o.Junk {
		name = path.Base(name)
	}
	if g.o.Transform != nil {
		t := g.o.Transform(name)
		if t == "" || t == "/" {
			return
		}
		name = t
	}
	m.Name = name

	if g.o.HaveOwner {
		m.UID = g.o.Owner
	}
	if g.o.HaveGroup {
		m.GID = g.o.Group
	}
	if !g.o.NumericOwner {
		m.Uname = g.lookup(g.users, m.UID, true)
		m.Gname = g.lookup(g.groups, m.GID, false)
	}

	if g.seen[m.Name] {
		g.warnf("%s: duplicate member, skipped", m.Name)
		return
	}
	g.seen[m.Name] = true
	if linkKey != nil {
		g.links[*linkKey] = m.Name
	}
	if g.o.OnName != nil {
		g.o.OnName(m.Name)
	}
	*g.out = append(*g.out, m)
}

func (g *gatherer) lookup(cache map[int]string, id int, isUser bool) string {
	if id == 0 {
		if isUser {
			return "root"
		}
		return "wheel" // best effort; readers fall back to uid/gid
	}
	if s, ok := cache[id]; ok {
		return s
	}
	var s string
	if isUser {
		if u, err := user.LookupId(fmt.Sprint(id)); err == nil {
			s = u.Username
		}
	} else {
		if gr, err := user.LookupGroupId(fmt.Sprint(id)); err == nil {
			s = gr.Name
		}
	}
	cache[id] = s
	return s
}
