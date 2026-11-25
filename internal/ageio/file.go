/*
Copyright (C) Philip Schlump, 2012-2026.

MIT Licensed.
*/

package ageio

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// ErrExists reports a destination that is already taken.  The age
// commands never replace an existing file.
var ErrExists = errors.New("already exists; existing files are not replaced")

// PublishedError reports a failure after the destination was
// published: the output is in place and complete, but its durability
// is in doubt.  That is a warning, not a lost file.
type PublishedError struct {
	Path string
	Err  error
}

func (e *PublishedError) Error() string {
	return fmt.Sprintf("%s was published, but %v", e.Path, e.Err)
}

func (e *PublishedError) Unwrap() error { return e.Err }

// File is a file output published whole or not at all.  Writes land
// in a 0600 temporary file in the destination directory; Commit, once
// every byte is written, sets the final mode, syncs and closes that
// file, and renames it into place.
//
// An existing destination is refused — before the temporary file is
// created and again just before the rename — never replaced.  A
// symlink counts as taken, dangling or not, and rename never follows
// one, so the target of a destination symlink is never overwritten.
// The destination path is not opened for writing at all: the input is
// read in full first, so an output can never truncate its own input.
type File struct {
	path string // the destination, as given
	tmp  string // the staged file beside it; "" once gone
	perm fs.FileMode
	f    *os.File // nil once committed or aborted
}

// CheckOutput clears path as the destination for an output read from
// src (nil for standard input): path must be free, and must not be
// the input's own file under another name.
func CheckOutput(path string, src *os.File) error {
	if src != nil {
		fi, err := os.Stat(path) // follows symlinks
		switch {
		case err == nil:
			if si, serr := src.Stat(); serr == nil && os.SameFile(fi, si) {
				return fmt.Errorf("input and output are the same file (%s)", path)
			}
		case !errors.Is(err, fs.ErrNotExist):
			return err
		}
	}
	return checkAbsent(path)
}

// checkAbsent fails with an error wrapping ErrExists when path is
// taken — by anything, a symlink or a directory included.
func checkAbsent(path string) error {
	_, err := os.Lstat(path)
	switch {
	case err == nil:
		return fmt.Errorf("%s: %w", path, ErrExists)
	case errors.Is(err, fs.ErrNotExist):
		return nil
	}
	return err
}

// Create stages a new file at path, to be published with perm on
// Commit.  It fails if path is already taken, so an existing output is
// refused before a byte is read.
func Create(path string, perm fs.FileMode) (*File, error) {
	if err := checkAbsent(path); err != nil {
		return nil, err
	}
	// A dot-prefixed, differently-suffixed name: a partial file never
	// matches the glob a script uses to find finished outputs.
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return nil, fmt.Errorf("cannot create a temporary file for %s: %w", path, err)
	}
	return &File{path: path, tmp: f.Name(), perm: perm, f: f}, nil
}

// Write appends to the staged file.
func (f *File) Write(p []byte) (int, error) {
	if f.f == nil {
		return 0, errors.New("write to a staged file that is already finished")
	}
	return f.f.Write(p)
}

// Commit publishes the staged file as the destination: it sets the
// final mode (explicitly, so the umask neither widens nor narrows it),
// syncs, closes, and renames it into place, then syncs the directory
// so the new name survives a crash.
//
// Commit fails with the staged file removed and nothing published if
// the destination appeared since Create.  The moment between that last
// check and the rename is the only opening a concurrent writer of the
// same name has to slip in; a name that must not be shared needs one
// writer.
func (f *File) Commit() error {
	if f.f == nil {
		return errors.New("the staged file is already finished")
	}
	err := f.f.Chmod(f.perm)
	if err == nil {
		err = f.f.Sync()
	}
	if cerr := f.f.Close(); err == nil {
		err = cerr
	}
	f.f = nil
	if err != nil {
		f.discard()
		return fmt.Errorf("cannot finish %s: %w", f.path, err)
	}
	if err := checkAbsent(f.path); err != nil {
		f.discard()
		return err
	}
	if err := os.Rename(f.tmp, f.path); err != nil {
		f.discard()
		return fmt.Errorf("cannot publish %s: %w", f.path, err)
	}
	f.tmp = ""
	if err := syncDir(filepath.Dir(f.path)); err != nil {
		// A filesystem that cannot sync a directory is not a failure.
		return &PublishedError{Path: f.path, Err: fmt.Errorf("its directory was not synced: %w", err)}
	}
	return nil
}

// Abort discards the staged file and leaves the destination
// untouched.  It is a no-op after Commit.
func (f *File) Abort() {
	if f.f != nil {
		_ = f.f.Close()
		f.f = nil
	}
	f.discard()
}

func (f *File) discard() {
	if f.tmp != "" {
		_ = os.Remove(f.tmp)
		f.tmp = ""
	}
}
