/*
Copyright (C) Philip Schlump, 2012-2026.

BSD 3 Clause Licensed.
*/

package eng

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/pschlump/xtar/internal/member"
	"github.com/pschlump/xtar/internal/pat"
	"github.com/pschlump/xtar/internal/safepath"
)

// Overwrite is the existing-file policy on extraction.
type Overwrite int

const (
	OvAlways  Overwrite = iota // tar default: replace
	OvNever                    // -k / --skip-old-files / unzip -n
	OvIfOlder                  // cpio default: replace only older files
	OvPrompt                   // unzip/7z default (auto-never without a tty)
)

// ExtractOpts is the extraction operation, dialect-independent.  The
// dialect maps its native flags onto these fields.
type ExtractOpts struct {
	Dest        string // extraction base directory
	Include     []*pat.Pattern
	Exclude     []*pat.Pattern
	ToStdout    bool                // -O / -p / -so
	Flatten     bool                // 7z e / unzip -j
	Strip       int                 // --strip-components
	Transform   func(string) string // rename members on the way out (GNU tar --transform)
	NoDirs      bool                // cpio without -d: members with missing parents are skipped
	Overwrite   Overwrite
	KeepPerms   bool // -p: apply stored permissions regardless of umask
	NoSameOwner bool
	Touch       bool // -m (tar): do not restore mtime
	Unsafe      bool // --unsafe-paths
	Warn        func(string)
	OnName      func(string)
	Prompt      func(question string) string // returns "" on EOF/refusal
	Confirm     func(name string) bool       // tar -w
}

type extractor struct {
	o       *ExtractOpts
	a       *Archive
	base    string
	hardIdx map[string]string // member name -> extracted path
	dataIdx map[string][]byte // member name -> data (for -O hard links)
	dirFix  []dirFix
	euid    int
	um      fs.FileMode
}

type dirFix struct {
	path  string
	mode  fs.FileMode
	mtime time.Time
}

// Extract writes the archive's members under o.Dest.  Non-fatal
// problems (skipped unsafe members, failed optional restores) go to
// o.Warn; the returned error is for fatal conditions only.
func Extract(a *Archive, o *ExtractOpts) error {
	if o.Dest == "" {
		o.Dest = "."
	}
	x := &extractor{
		o:       o,
		a:       a,
		base:    o.Dest,
		hardIdx: map[string]string{},
		dataIdx: map[string][]byte{},
		euid:    os.Geteuid(),
		um:      currentUmask(),
	}
	// The destination itself is trusted (the caller chose it); make
	// sure it exists before members are laid out under it.
	if err := os.MkdirAll(x.base, 0o755); err != nil {
		return err
	}
	for i := range a.Members {
		x.one(&a.Members[i])
	}
	x.finishDirs()
	return nil
}

func (x *extractor) warnf(format string, args ...any) {
	if x.o.Warn != nil {
		x.o.Warn(fmt.Sprintf(format, args...))
	}
}

func (x *extractor) one(m *member.Member) {
	name := m.Name
	if strings.HasPrefix(name, "/") {
		// GNU tar/cpio default: strip absolute member names down to
		// relative ones rather than skipping them.
		x.warnf("member %s: stripping leading '/' from member name", name)
		name = strings.TrimPrefix(name, "/")
	}
	if !pat.IncludeMatch(x.o.Include, name) {
		return
	}
	if pat.ExcludeMatch(x.o.Exclude, name) {
		return
	}
	if x.o.Strip > 0 {
		parts := strings.Split(name, "/")
		if len(parts) <= x.o.Strip {
			return // the member vanishes (GNU tar semantics)
		}
		name = strings.Join(parts[x.o.Strip:], "/")
	}
	if x.o.Transform != nil {
		name = x.o.Transform(name)
		if name == "" || name == "/" {
			return
		}
	}

	if x.o.ToStdout {
		if m.Kind == member.Regular {
			if x.o.OnName != nil {
				x.o.OnName(name)
			}
			os.Stdout.Write(m.Data)
		} else if m.Kind == member.HardLink {
			if d, ok := x.dataIdx[m.LinkName]; ok {
				if x.o.OnName != nil {
					x.o.OnName(name)
				}
				os.Stdout.Write(d)
			}
		}
		x.record(m.Name, name, m, "")
		return
	}

	if x.o.Flatten {
		name = path.Base(name)
		if name == "/" || name == "." {
			return
		}
	}

	if x.o.Confirm != nil && !x.o.Confirm(name) {
		return
	}
	if x.o.OnName != nil {
		x.o.OnName(name)
	}

	dest, err := safepath.Join(x.base, name)
	if err != nil {
		x.warnf("member %s skipped: %v", m.Name, err)
		return
	}

	switch m.Kind {
	case member.Directory:
		x.extractDir(m, dest)
	case member.Regular:
		x.extractFile(m, dest)
	case member.SymLink:
		x.extractSymlink(m, dest)
	case member.HardLink:
		x.extractHardLink(m, dest)
	case member.FIFO:
		x.extractSpecial(m, dest, "fifo")
	case member.CharDev, member.BlockDev:
		x.extractSpecial(m, dest, "device")
	}
	x.record(m.Name, name, m, dest)
}

// record remembers where a member landed for later hard links, keyed
// by both the raw archive name (hard-link targets are archive names)
// and the displayed/stripped/transformed name.
func (x *extractor) record(orig, disp string, m *member.Member, dest string) {
	if dest != "" {
		x.hardIdx[orig] = dest
		x.hardIdx[disp] = dest
	}
	if m.Data != nil {
		x.dataIdx[orig] = m.Data
		x.dataIdx[disp] = m.Data
	}
}

// ensureParent creates (or, with NoDirs, requires) the parent
// directory of dest, guarding against symlink traversal below the
// extraction base.
func (x *extractor) ensureParent(m *member.Member, dest string) bool {
	if x.o.NoDirs {
		parent := filepath.Dir(dest)
		if fi, err := os.Lstat(parent); err != nil || !fi.IsDir() {
			x.warnf("member %s skipped: %s does not exist (use -d to create leading directories)", m.Name, parent)
			return false
		}
		return true
	}
	if _, err := safepath.EnsureParent(x.base, dest, x.o.Unsafe); err != nil {
		x.warnf("member %s skipped: %v", m.Name, err)
		return false
	}
	return true
}

func (x *extractor) extractDir(m *member.Member, dest string) {
	if !x.ensureParent(m, dest) {
		return
	}
	if fi, err := os.Lstat(dest); err == nil {
		if !fi.IsDir() {
			x.warnf("member %s skipped: %s exists and is not a directory", m.Name, dest)
			return
		}
	} else if err := os.Mkdir(dest, 0o755); err != nil {
		x.warnf("member %s: mkdir: %v", m.Name, err)
		return
	}
	// Permissions and mtime are applied at the end (after members
	// inside the directory have been written).
	x.dirFix = append(x.dirFix, dirFix{path: dest, mode: x.applyUmask(member.ToFileMode(m.Mode)), mtime: m.ModTime})
}

func (x *extractor) extractFile(m *member.Member, dest string) {
	if !x.ensureParent(m, dest) {
		return
	}
	ok, dest := x.decide(m, dest, false)
	if !ok {
		return
	}
	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o666)
	if err != nil {
		x.warnf("member %s: create: %v", m.Name, err)
		return
	}
	if _, err := f.Write(m.Data); err != nil {
		f.Close()
		x.warnf("member %s: write: %v", m.Name, err)
		return
	}
	if err := f.Close(); err != nil {
		x.warnf("member %s: close: %v", m.Name, err)
		return
	}
	x.restore(m, dest)
}

func (x *extractor) extractSymlink(m *member.Member, dest string) {
	target := m.LinkName
	if strings.HasPrefix(target, "/") {
		x.warnf("member %s: stripping leading '/' from link target %s", m.Name, target)
		target = strings.TrimPrefix(target, "/")
	}
	if !x.ensureParent(m, dest) {
		return
	}
	ok, dest := x.decide(m, dest, false)
	if !ok {
		return
	}
	os.Remove(dest)
	if err := os.Symlink(target, dest); err != nil {
		x.warnf("member %s: symlink: %v", m.Name, err)
	}
}

func (x *extractor) extractHardLink(m *member.Member, dest string) {
	target, found := x.hardIdx[m.LinkName]
	if !found {
		x.warnf("member %s skipped: hard-link target %q was not extracted", m.Name, m.LinkName)
		return
	}
	if !x.ensureParent(m, dest) {
		return
	}
	ok, dest := x.decide(m, dest, false)
	if !ok {
		return
	}
	os.Remove(dest)
	if err := os.Link(target, dest); err != nil {
		x.warnf("member %s: hard link: %v", m.Name, err)
	}
}

func (x *extractor) extractSpecial(m *member.Member, dest, what string) {
	if !x.ensureParent(m, dest) {
		return
	}
	ok, dest := x.decide(m, dest, false)
	if !ok {
		return
	}
	dev := uint32(m.DevMajor)<<8 | uint32(m.DevMinor)
	if err := makeSpecial(dest, what, x.applyUmask(member.ToFileMode(m.Mode)), dev, x.euid); err != nil {
		x.warnf("member %s: %s: %v", m.Name, what, err)
	}
}

// decide applies the overwrite policy to an existing path.  The
// returned string is the destination to use; it differs from dest only
// after an interactive rename.
func (x *extractor) decide(m *member.Member, dest string, isDir bool) (bool, string) {
	fi, err := os.Lstat(dest)
	if err != nil {
		return true, dest // does not exist yet
	}
	switch x.o.Overwrite {
	case OvNever:
		x.warnf("member %s skipped: %s already exists", m.Name, dest)
		return false, dest
	case OvIfOlder:
		// Only regular files carry a comparable mtime: symlinks (whose
		// times are never restored) and specials are simply replaced.
		// Compare at the second precision containers store; nanosecond
		// comparison would make every equal-mtime file look newer.
		if fi.Mode().IsRegular() && fi.ModTime().Unix() > m.ModTime.Unix() {
			x.warnf("member %s skipped: %s is newer (use -u to replace)", m.Name, dest)
			return false, dest
		}
		return true, dest // existing file is older or equal: replace
	case OvPrompt:
		return x.promptReplace(m, dest)
	default: // OvAlways
		if fi.IsDir() && !isDir {
			x.warnf("member %s skipped: %s is a directory", m.Name, dest)
			return false, dest
		}
		return true, dest
	}
}

func (x *extractor) promptReplace(m *member.Member, dest string) (bool, string) {
	if x.o.Prompt == nil {
		x.warnf("member %s skipped: %s already exists", m.Name, dest)
		return false, dest
	}
	for {
		ans := x.o.Prompt(fmt.Sprintf("replace %s? [y]es, [n]o, [A]ll, [N]one, [r]ename: ", dest))
		switch strings.ToLower(strings.TrimSpace(ans)) {
		case "y", "yes":
			return true, dest
		case "a", "all":
			x.o.Overwrite = OvAlways
			return true, dest
		case "n", "no", "":
			if ans == "" {
				x.warnf("member %s skipped: EOF on stdin at replace prompt", m.Name)
			}
			return false, dest
		case "none", "q":
			x.o.Overwrite = OvNever
			return false, dest
		case "r", "rename":
			newName := strings.TrimSpace(x.o.Prompt("new name: "))
			if newName == "" {
				continue
			}
			nd, err := safepath.Join(x.base, newName)
			if err != nil {
				x.warnf("rename: %v", err)
				return false, dest
			}
			if _, err := os.Lstat(nd); err == nil {
				x.warnf("rename: %s already exists", nd)
				continue
			}
			return true, nd
		default:
			continue
		}
	}
}

// restore applies permissions/ownership/mtime to an extracted file.
func (x *extractor) restore(m *member.Member, dest string) {
	mode := x.applyUmask(member.ToFileMode(m.Mode))
	if x.o.KeepPerms || x.euid == 0 {
		mode = member.ToFileMode(m.Mode)
	}
	if err := os.Chmod(dest, mode); err != nil {
		x.warnf("member %s: chmod: %v", m.Name, err)
	}
	if x.euid == 0 && !x.o.NoSameOwner && (m.UID != 0 || m.GID != 0) {
		if err := os.Chown(dest, m.UID, m.GID); err != nil {
			x.warnf("member %s: chown: %v", m.Name, err)
		}
	}
	if !x.o.Touch && !m.ModTime.IsZero() {
		if err := os.Chtimes(dest, m.ModTime, m.ModTime); err != nil {
			// not fatal: common when not the file's owner
			_ = err
		}
	}
}

func (x *extractor) applyUmask(mode fs.FileMode) fs.FileMode {
	if x.o.KeepPerms || x.euid == 0 {
		return mode
	}
	return (mode &^ 0o777) | (mode.Perm() &^ x.um)
}

func (x *extractor) finishDirs() {
	// Deepest first so restrictive modes cannot block children writes.
	for i := len(x.dirFix) - 1; i >= 0; i-- {
		d := x.dirFix[i]
		os.Chmod(d.path, d.mode.Perm())
		if !x.o.Touch && !d.mtime.IsZero() {
			os.Chtimes(d.path, d.mtime, d.mtime)
		}
	}
}
