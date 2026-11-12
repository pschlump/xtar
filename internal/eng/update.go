/*
Copyright (C) Philip Schlump, 2012-2026.

BSD 3 Clause Licensed.
*/

package eng

import (
	"fmt"
	"os"
	"time"

	"github.com/pschlump/xtar/internal/member"
	"github.com/pschlump/xtar/internal/pat"
	"github.com/pschlump/xtar/internal/tarfmt"
	"github.com/pschlump/xtar/internal/walk"
)

// UpdateOpts is the tar -r/-u/-A/--delete family: modify an existing
// archive in place.  Which parts apply is decided by which fields are
// set: Delete patterns remove members, Concat archives are appended
// (-A), and Walk.Files members are appended (-r) or replace-older (-u).
// The archive is rebuilt whole (the whole-buffer model); compressed
// archives are refused the way GNU tar does.
type UpdateOpts struct {
	Path   string
	Format string // write-variant override; "" keeps the source variant
	Delete []*pat.Pattern
	Concat []string // -A source archives
	Walk   walk.Opts
	Update bool // -u: skip files not newer than the archived copy
	Warn   func(string)
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
	a, err := OpenFile(o.Path, "")
	if err != nil {
		return nil, err
	}
	if len(a.Layers) > 0 {
		return nil, fmt.Errorf("%s: cannot update compressed archives", o.Path)
	}
	if a.Format != "tar" {
		return nil, fmt.Errorf("%s: only tar archives can be updated in place (this is %s)", o.Path, a.Format)
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
		sa, err := OpenFile(src, "")
		if err != nil {
			return nil, err
		}
		if sa.Format != "tar" || len(sa.Layers) > 0 {
			return nil, fmt.Errorf("%s: only plain tar archives can be concatenated", src)
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
				if at, ok := archived[m.Name]; ok && !m.ModTime.After(at) {
					continue // the archived copy is at least as new
				}
				keep = append(keep, m)
			}
			fresh = keep
		}
		mems = append(mems, fresh...)
		res.Appended = len(fresh)
	}

	format := o.Format
	if format == "" {
		format = a.Variant
	}
	blob, err := tarfmt.Build(format, mems)
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
