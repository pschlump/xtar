/*
Copyright (C) Philip Schlump, 2012-2026.

MIT Licensed.
*/

package eng

import (
	"fmt"
	"os"
	"time"

	"github.com/pschlump/xtar/internal/cpiofmt"
	"github.com/pschlump/xtar/internal/member"
	"github.com/pschlump/xtar/internal/pat"
	"github.com/pschlump/xtar/internal/sevenzfmt"
	"github.com/pschlump/xtar/internal/tarfmt"
	"github.com/pschlump/xtar/internal/walk"
	"github.com/pschlump/xtar/internal/zipfmt"
)

// UpdateOpts is the tar -r/-u/-A/--delete family: modify an existing
// archive in place.  Which parts apply is decided by which fields are
// set: Delete patterns remove members, Concat archives are appended
// (-A), and Walk.Files members are appended (-r) or replace-older (-u).
// The archive is rebuilt whole (the whole-buffer model); compressed
// archives are refused the way GNU tar does.
type UpdateOpts struct {
	Path         string
	Format       string // write-variant override; "" keeps the source variant
	Delete       []*pat.Pattern
	Concat       []string // -A source archives
	Walk         walk.Opts
	Update       bool // -u: skip files not newer than the archived copy
	Password     string
	Level        int              // compression level for rebuilds (7z); 0 stores, -1 defaults
	SevenZMethod sevenzfmt.Method // 7z folder codec for rebuilds
	ZipMethod    int              // zipfmt.Method*; -1 (unset) defaults to deflate
	ZipPPMd      zipfmt.PPMdOpts  // method-98 model knobs when rebuilding zip
	Warn         func(string)
}

// UpdateResult reports what an Update did.
type UpdateResult struct {
	Deleted      int
	Appended     int
	Concatenated int
	Members      int   // members in the rewritten archive
	Bytes        int64 // size of the rewritten archive
}

// Update rewrites the archive at o.Path.
func Update(o *UpdateOpts) (*UpdateResult, error) {
	if o.Path == "" || o.Path == "-" {
		return nil, fmt.Errorf("options '-Aru' and '--delete' cannot work on an archive on standard input/output")
	}
	// The rewrite is whole-buffer by construction (members are rebuilt
	// from scratch), so decode the source that way too.
	data, err := os.ReadFile(o.Path)
	if err != nil {
		return nil, err
	}
	a, err := decode(data, o.Password, o.Path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", o.Path, err)
	}
	if len(a.Layers) > 0 {
		return nil, fmt.Errorf("%s: cannot update compressed archives", o.Path)
	}
	if a.Format != "tar" && a.Format != "cpio" && a.Format != "zip" && a.Format != "7z" {
		return nil, fmt.Errorf("%s: only tar, cpio, zip, and 7z archives can be updated in place (this is %s)", o.Path, a.Format)
	}

	res := &UpdateResult{}
	mems := a.Members

	if len(o.Delete) > 0 {
		kept := make([]member.Member, 0, len(mems))
		for _, m := range mems {
			if pat.ExcludeMatch(o.Delete, m.Name) {
				res.Deleted++
				continue
			}
			kept = append(kept, m)
		}
		mems = kept
	}

	for _, src := range o.Concat {
		cdata, err := os.ReadFile(src)
		if err != nil {
			return nil, err
		}
		sa, err := decode(cdata, "", src)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", src, err)
		}
		if len(sa.Layers) > 0 || (sa.Format != "tar" && sa.Format != "cpio") {
			return nil, fmt.Errorf("%s: only plain tar and cpio archives can be concatenated", src)
		}
		mems = append(mems, sa.Members...)
		res.Concatenated += len(sa.Members)
	}

	if len(o.Walk.Files) > 0 || o.Walk.StdinList {
		w := o.Walk
		if !w.NoRecursion {
			w.Recurse = true
		}
		fresh, err := walk.Gather(&w)
		if err != nil {
			return nil, err
		}
		if o.Update {
			archived := make(map[string]time.Time, len(mems))
			for _, m := range mems {
				archived[m.Name] = m.ModTime // a later copy wins, like extraction does
			}
			keep := make([]member.Member, 0, len(fresh))
			for _, m := range fresh {
				if at, ok := archived[m.Name]; ok && m.ModTime.Unix() <= at.Unix() {
					continue // the archived copy is at least as new (container mtime precision is seconds)
				}
				keep = append(keep, m)
			}
			fresh = keep
		}
		mems = append(mems, fresh...)
		res.Appended = len(fresh)
	}

	// Zip members that came from an archive keep their stored form
	// (compressed bytes untouched; encrypted entries need no password);
	// fresh members get the requested method.
	for i := range mems {
		if a.Format != "zip" {
			continue
		}
		if mems[i].Raw != nil {
			mems[i].KeepStored = true
		} else if o.ZipMethod >= 0 {
			mems[i].Method = uint16(o.ZipMethod)
		} else {
			mems[i].Method = zipfmt.MethodDeflate
		}
	}

	format := o.Format
	if format == "" {
		format = a.Variant
	}
	var blob []byte
	switch a.Format {
	case "tar":
		blob, err = tarfmt.Build(format, mems)
	case "cpio":
		blob, err = cpiofmt.Build(format, mems)
	case "7z":
		blob, err = sevenzfmt.Build(mems, o.Password, o.Level, o.SevenZMethod)
	case "zip":
		blob, err = zipfmt.Build(mems, a.Comment, "", o.ZipPPMd)
	}
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(o.Path, blob, 0o666); err != nil {
		return nil, err
	}
	res.Members = len(mems)
	res.Bytes = int64(len(blob))
	return res, nil
}
