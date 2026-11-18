/*
Copyright (C) Philip Schlump, 2012-2026.

MIT Licensed.
*/

package eng

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// maxSplitParts bounds a split set so a hostile directory of parts
// cannot make the assembler read forever.
const maxSplitParts = 10000

// splitSet reports whether path belongs to a split zip set — numbered
// parts `base.z01`…`base.zNN` beside a final `base.zip` — and returns
// the parts in concatenation order.  Opening any member of the set
// assembles the whole archive, the way zip -s- merges one.
func splitSet(path string) ([]string, bool) {
	dir, file := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	ext := filepath.Ext(file)
	var base string
	switch {
	case strings.EqualFold(ext, ".zip"):
		base = strings.TrimSuffix(file, ext)
	case len(ext) >= 3 && ext[1] == 'z' && isDigits(ext[2:]):
		base = strings.TrimSuffix(file, ext) // opening one part opens the set
	default:
		return nil, false
	}

	// The set is real only when numbered parts sit beside the .zip.
	last := filepath.Join(dir, base+".zip")
	if _, err := os.Stat(last); err != nil {
		return nil, false
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, false
	}
	var nums []int
	for _, de := range entries {
		name := de.Name()
		e := filepath.Ext(name)
		if len(e) < 3 || e[1] != 'z' || !isDigits(e[2:]) {
			continue // zip names parts lowercase; anything else is not ours
		}
		if name[:len(name)-len(e)] != base {
			continue
		}
		if n, err := strconv.Atoi(e[2:]); err == nil && n >= 1 && n <= maxSplitParts {
			nums = append(nums, n)
		}
	}
	if len(nums) == 0 {
		return nil, false
	}
	sort.Ints(nums)
	if nums[len(nums)-1] != len(nums) {
		return nil, false // a gap in the sequence: the set is incomplete
	}
	parts := make([]string, 0, len(nums)+1)
	for _, n := range nums {
		parts = append(parts, splitPartName(dir, base, n))
	}
	return append(parts, last), true
}

// splitPartName formats part n of a set: .z01 through .z99 are
// zero-padded to two, later parts carry no padding (zip's convention).
func splitPartName(dir, base string, n int) string {
	if n < 100 {
		return filepath.Join(dir, fmt.Sprintf("%s.z%02d", base, n))
	}
	return filepath.Join(dir, fmt.Sprintf("%s.z%d", base, n))
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// openSplitZip concatenates the parts of a split set and parses the
// joined stream.  Split writers state every offset relative to the
// part it lands in, so zipfmt's recovery parse rebuilds them on the
// assembled bytes; unzip(1) cannot read a set at all without merging
// it first (zip -s-).
func openSplitZip(path string, parts []string, password string) (*Archive, error) {
	var buf bytes.Buffer
	for _, p := range parts {
		f, err := os.Open(p)
		if err != nil {
			return nil, err
		}
		_, err = io.Copy(&buf, f)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return nil, err
		}
	}
	a, err := decode(buf.Bytes(), password, parts[len(parts)-1])
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	a.Path = path
	a.CompSize = int64(buf.Len())
	a.Notes = append(a.Notes, fmt.Sprintf("split zip: assembled %d parts (%s … %s)",
		len(parts), filepath.Base(parts[0]), filepath.Base(parts[len(parts)-1])))
	return a, nil
}
