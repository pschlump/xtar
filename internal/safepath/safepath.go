/*
Copyright (C) Philip Schlump, 2012-2026.

BSD 3 Clause Licensed.
*/

// Package safepath contains the extraction-side path rules shared by
// every dialect: member names may not escape the destination, and
// extraction never passes through an existing symlink.
package safepath

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Join returns the filesystem path for the member name rel under
// base, rejecting names that could escape the destination directory
// (absolute paths, "..", empty results).
func Join(base, rel string) (string, error) {
	rel = strings.TrimPrefix(rel, "./")
	c := path.Clean(rel)
	if c == "." || c == "" {
		return "", fmt.Errorf("member %q has an empty path", rel)
	}
	if c == ".." || strings.HasPrefix(c, "../") {
		return "", fmt.Errorf("member %q contains '..' and would escape the destination", rel)
	}
	if strings.HasPrefix(c, "/") {
		return "", fmt.Errorf("member %q is an absolute path", rel)
	}
	return filepath.Join(base, filepath.FromSlash(c)), nil
}

// EnsureParent creates the missing parent directories of full with
// mode 0755, refusing to pass through an existing symlink (the classic
// "member a/symlink + member a/symlink/../../etc" attack) unless
// unsafe is set.  Only the part of the path below root is checked:
// root is the caller-chosen destination and is trusted (on macOS, for
// instance, it may legitimately live under the system /var symlink).
// It returns the directories it created, in creation order.
func EnsureParent(root, full string, unsafe bool) ([]string, error) {
	rel, err := filepath.Rel(root, filepath.Dir(full))
	if err != nil {
		return nil, err
	}
	var created []string
	p := root
	for _, s := range strings.Split(filepath.ToSlash(rel), "/") {
		if s == "" || s == "." {
			continue
		}
		p = filepath.Join(p, s)
		fi, err := os.Lstat(p)
		if err == nil {
			if fi.Mode()&os.ModeSymlink != 0 {
				if !unsafe {
					return nil, fmt.Errorf("refusing to extract through symlink %s", p)
				}
				continue
			}
			if !fi.IsDir() {
				return nil, fmt.Errorf("%s exists and is not a directory", p)
			}
			continue
		}
		if err := os.Mkdir(p, 0o755); err != nil {
			return nil, err
		}
		created = append(created, p)
	}
	return created, nil
}
