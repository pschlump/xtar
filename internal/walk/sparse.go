/*
Copyright (C) Philip Schlump, 2012-2026.

BSD 3 Clause Licensed.
*/

package walk

import (
	"os"
	"syscall"

	"github.com/pschlump/xtar/internal/member"
)

// blockSize is the tar record size, the granularity holes are scanned
// at (GNU tar scans the same way).
const blockSize = 512

// readSparse loads a regular file as a sparse member when it has
// holes: filesystem extents when SEEK_DATA/SEEK_HOLE report them,
// otherwise a block-granular scan for zero runs (GNU tar's "raw"
// fallback, which also catches zero-filled regions on filesystems
// that allocate holes — like APFS).  Files without holes come back
// dense (nil spans).  A trailing hole gets a zero-length marker
// extent, the GNU convention.
func readSparse(path string, size int64) (data []byte, spans []member.SparseSpan, err error) {
	if size <= blockSize {
		return readWhole(path) // nothing sparse below one block (GNU's rule)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = f.Close() }()

	extents := seekExtents(f, size)
	if extents == nil {
		extents = scanExtents(f, size)
		if extents == nil {
			return readWhole(path) // the scanner found no holes
		}
	}
	if len(extents) == 1 && extents[0].Off == 0 && extents[0].Len >= size {
		return readWhole(path) // no holes after all
	}
	if len(extents) == 0 {
		extents = []member.SparseSpan{{Off: size, Len: 0}} // the whole file is a hole
	} else if end := extents[len(extents)-1].Off + extents[len(extents)-1].Len; end < size {
		// A trailing hole gets a zero-length marker so the logical
		// size survives formats that store it only implicitly.
		extents = append(extents, member.SparseSpan{Off: size, Len: 0})
	}

	buf := make([]byte, 0, 64*1024)
	tmp := make([]byte, 32*1024)
	for _, sp := range extents {
		if sp.Len == 0 {
			continue
		}
		for left := sp.Len; left > 0; {
			n := int64(len(tmp))
			if left < n {
				n = left
			}
			if _, err := f.ReadAt(tmp[:n], sp.Off+(sp.Len-left)); err != nil {
				return nil, nil, err
			}
			buf = append(buf, tmp[:n]...)
			left -= n
		}
	}
	return buf, extents, nil
}

// readWhole is the dense fallback.
func readWhole(path string) ([]byte, []member.SparseSpan, error) {
	b, err := os.ReadFile(path)
	return b, nil, err
}

// seekExtents probes the filesystem's own extent map through
// SEEK_DATA/SEEK_HOLE.  It returns nil when the filesystem cannot (or
// does not) report holes — including the whole-file-is-data answer,
// which may simply mean the holes were allocated — so the caller can
// fall back to scanning the content.
func seekExtents(f *os.File, size int64) []member.SparseSpan {
	const seekData, seekHole = 3, 4 // lseek whences (darwin and linux)
	fd := int(f.Fd())
	var out []member.SparseSpan
	pos := int64(0)
	for pos < size {
		d, err := syscall.Seek(fd, pos, seekData)
		if err != nil || d >= size {
			return nil
		}
		h, err := syscall.Seek(fd, d, seekHole)
		if err != nil {
			return nil
		}
		out = append(out, member.SparseSpan{Off: d, Len: h - d})
		pos = h
	}
	if len(out) == 1 && out[0].Off == 0 && out[0].Len >= size {
		return nil // fully allocated: no FS-level holes
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// scanExtents reads the file block by block and treats runs of zero
// blocks as holes — block-granular extents, the way GNU tar's raw
// scanner works.  Nil means no holes were found; an empty non-nil
// slice means the whole file is zeros.
func scanExtents(f *os.File, size int64) []member.SparseSpan {
	var out []member.SparseSpan
	sawData := false
	last := -1 // index of the extent being extended
	blk := make([]byte, blockSize)
	for off := int64(0); off < size; {
		n, err := f.ReadAt(blk, off)
		if n == 0 {
			break
		}
		if !isZero(blk[:n]) {
			sawData = true
			if last >= 0 {
				out[last].Len += int64(n)
			} else {
				out = append(out, member.SparseSpan{Off: off, Len: int64(n)})
				last = len(out) - 1
			}
		} else {
			last = -1
		}
		off += int64(n)
		if err != nil {
			break // short read: what we have is the map
		}
	}
	if !sawData {
		return []member.SparseSpan{} // the whole file is zeros
	}
	if len(out) == 1 && out[0].Off == 0 && out[0].Len >= size {
		return nil // one solid extent: dense
	}
	return out
}

func isZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
