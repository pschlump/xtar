/*
Copyright (C) Philip Schlump, 2012-2026.

BSD 3 Clause Licensed.
*/

// Package tarfmt reads and writes the tar container: pre-POSIX v7,
// POSIX ustar, GNU (including the L/K long-name records and base-256
// numbers), and PAX extended headers on read; gnu (default), ustar,
// pax and v7 on write.
package tarfmt

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/pschlump/xtar/internal/member"
	"github.com/pschlump/xtar/internal/sniff"
)

const blockSize = 512

// Archive is a parsed tar container.
type Archive struct {
	Variant string // "v7", "ustar", "ustar+pax", "gnu", "gnu+pax"
	Members []member.Member
	Notes   []string // non-fatal observations ("volume header ignored", ...)
}

// WriteFormat maps a parsed variant back to a build format name.
func (a *Archive) WriteFormat() string {
	if strings.HasSuffix(a.Variant, "+pax") {
		return "pax"
	}
	return a.Variant // "v7", "ustar", "gnu"
}

// Parse decodes a tar container from b, loading every member's data:
// the whole-buffer form of the streaming Reader.
func Parse(b []byte) (*Archive, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	r := NewReader(bytes.NewReader(b))
	mems, err := readAll(r)
	if err != nil {
		return nil, err
	}
	a := &Archive{Variant: r.Variant(), Members: mems, Notes: r.Notes()}
	if r.PAXSeen() {
		a.Variant += "+pax"
	}
	return a, nil
}

// readAll drains a Reader into fully-materialized members.
func readAll(r *Reader) ([]member.Member, error) {
	var out []member.Member
	for {
		m, err := r.Next()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if m.Kind == member.Regular || m.Kind == member.Directory {
			data, err := io.ReadAll(r)
			if err != nil {
				return nil, err
			}
			want := m.Size
			if m.Sparse != nil {
				want = 0 // sparse: the extents' tight concatenation
				for _, s := range m.Sparse {
					want += s.Len
				}
			}
			if int64(len(data)) != want {
				return nil, fmt.Errorf("truncated archive: member %q", m.Name)
			}
			m.Data = data
		}
		out = append(out, *m)
	}
}

// ------------------------------------------------------------------
// Streaming read side
// ------------------------------------------------------------------

// Reader decodes a tar stream one member at a time: Next advances to
// the next member and Read streams the current member's content.  An
// archive of any size can be read through it (through a compression
// layer, from a pipe) without materializing the container.  Regular
// members arrive with Data unset (their content streams through
// Read); a symlink's Data carries its target, as Parse produces.
type Reader struct {
	br         *bufio.Reader
	pos        int64 // bytes consumed, for error messages
	left       int64 // bytes remaining in the current member's data
	pad        int64 // block padding after the current member's data
	variant    string
	variantSet bool
	paxSeen    bool
	pending    map[string]string // pax/GNU records for the next member
	global     map[string]string
	notes      []string
	done       bool
	err        error

	// Sparse state.  spans is the current member's map (nil = dense);
	// Read serves each extent's bytes tight, skipping the per-extent
	// block padding, so the data a visitor sees (and Parse buffers)
	// is the extents' concatenation, not the stored form.
	spans         []member.SparseSpan
	spIdx         int   // extent being served
	spOff         int64 // bytes served from it
	sparsePending bool  // pax 1.0: the map rides in the first data blocks
	sparseNext    bool  // the next member is sparse (map already known)
	mapBlocks     int   // pax 1.0: map blocks consumed for this member
	// pax 0.0 records repeat GNU.sparse.offset/numbytes, which a map
	// collapses; they are collected in order instead.
	spOffs, spLens []int64
}

// maxRecord caps the inline records (pax headers, GNU long names) so
// a crafted size field cannot make the reader allocate wildly.
const maxRecord = 1 << 20

// NewReader starts decoding the tar stream on r.
func NewReader(r io.Reader) *Reader {
	return &Reader{
		br:      bufio.NewReaderSize(r, 128*1024),
		variant: "v7",
		pending: map[string]string{},
		global:  map[string]string{},
	}
}

// Variant reports the format variant; "v7" until the first header.
func (t *Reader) Variant() string { return t.variant }

// PAXSeen reports whether any pax extended headers were read.
func (t *Reader) PAXSeen() bool { return t.paxSeen }

// Notes reports the non-fatal observations so far.
func (t *Reader) Notes() []string { return t.notes }

func (t *Reader) fail(err error) error {
	if t.err == nil {
		t.err = err
	}
	return t.err
}

// Next advances to the next member, discarding whatever is left of
// the current one's data.  io.EOF ends the archive.
func (t *Reader) Next() (*member.Member, error) {
	if t.err != nil {
		return nil, t.err
	}
	if t.done {
		return nil, io.EOF
	}
	if err := t.skipData(); err != nil {
		return nil, t.fail(err)
	}
	t.spans, t.spIdx, t.spOff = nil, 0, 0
	t.sparsePending, t.sparseNext, t.mapBlocks = false, false, 0
	t.spOffs, t.spLens = t.spOffs[:0], t.spLens[:0]
	blk := make([]byte, blockSize)
	for {
		n, err := io.ReadFull(t.br, blk)
		t.pos += int64(n)
		if err != nil {
			// Ended without an end-of-archive marker: the whole-buffer
			// parse tolerated that, noting only a short non-zero tail.
			if n > 0 && !allZero(blk[:n]) {
				t.notes = append(t.notes, "trailing bytes after end-of-archive ignored")
			}
			t.done = true
			return nil, io.EOF
		}
		if allZero(blk) {
			t.probeTrailing()
			t.done = true
			return nil, io.EOF
		}
		if !sniff.HeaderChecksumOK(blk) {
			return nil, t.fail(fmt.Errorf("header checksum mismatch at offset %d (this does not look like a tar archive)", t.pos-blockSize))
		}
		h := decodeHeader(blk)
		if !t.variantSet {
			switch h.magic {
			case "ustar\x00":
				t.variant = "ustar"
			case "ustar ":
				t.variant = "gnu"
			default:
				t.variant = "v7"
			}
			t.variantSet = true
		}
		if h.size < 0 {
			return nil, t.fail(fmt.Errorf("member %q has a negative size", h.name))
		}

		// Pseudo-members: their content is part of the header stream
		// and never surfaces as a member.
		switch h.typeflag {
		case 'x', 'X', 'g', 'L', 'K':
			data, err := t.readInline(h.name, h.size)
			if err != nil {
				return nil, t.fail(err)
			}
			t.applyRecord(h.typeflag, data)
			continue
		case 'V', 'M', 'D':
			if err := t.skipInline(h.name, h.size); err != nil {
				return nil, t.fail(err)
			}
			switch h.typeflag {
			case 'V':
				t.notes = append(t.notes, "volume header ignored")
			case 'M':
				t.notes = append(t.notes, "multi-volume member skipped")
			case 'D':
				t.notes = append(t.notes, "dump directory entry ignored")
			}
			continue
		case 'S':
			if err := t.readOldgnuSparse(h); err != nil {
				return nil, t.fail(err)
			}
		}

		m, err := t.buildMember(h)
		if err != nil {
			return nil, t.fail(err)
		}
		if t.sparseNext && t.sparsePending {
			// pax 1.0: the map rides in the member's first data blocks
			if err := t.readSparseMap(m.Name); err != nil {
				return nil, t.fail(err)
			}
			m.Sparse = t.spans
			if err := validateSpans(m.Name, t.spans, m.Size); err != nil {
				return nil, t.fail(err)
			}
		}
		t.left = h.size
		t.pad = int64(padUp(int(h.size), blockSize)) - h.size
		if t.spans != nil {
			// Sparse members are consumed extent by extent (each
			// padded to a block, the 1.0 map blocks already read),
			// which is what the stream physically holds — the
			// declared size may be the tight sum instead.
			t.left, t.pad = m.StoredSize(), 0
		}
		return m, nil
	}
}

// readOldgnuSparse consumes the old GNU sparse ('S') map: up to four
// extents in the header itself, then as many extension sparse headers
// (21 extents each, isextended at byte 504) as it takes.  The spans
// land in t.spans for buildMember.
func (t *Reader) readOldgnuSparse(h readHdr) error {
	var spans []member.SparseSpan
	add := func(off, num int64) bool {
		if off == 0 && num == 0 {
			return false // an empty slot terminates the map
		}
		spans = append(spans, member.SparseSpan{Off: off, Len: num})
		return true
	}
	for i := 0; i < 4; i++ {
		if !add(h.sparse[i][0], h.sparse[i][1]) {
			break
		}
	}
	blk := make([]byte, blockSize)
	for h.sparseExt {
		n, err := io.ReadFull(t.br, blk)
		t.pos += int64(n)
		if err != nil {
			return fmt.Errorf("truncated archive: sparse extension header: %w", err)
		}
		h.sparseExt = blk[504] == '1'
		for i := 0; i < 21; i++ {
			off, num := numeric(blk[24*i:24*i+12]), numeric(blk[24*i+12:24*i+24])
			if !add(off, num) {
				break
			}
		}
	}
	t.spans = spans
	t.sparseNext = true
	return nil
}

// readSparseMap parses the pax 1.0 sparse map from the member's
// leading data blocks: newline-terminated decimal numbers (a count,
// then offset/length pairs), NUL-padded to a block boundary.
func (t *Reader) readSparseMap(name string) error {
	var nums []int64
	var carry []byte
	complete := false
	want := -1
	blk := make([]byte, blockSize)
	for !complete {
		n, err := io.ReadFull(t.br, blk)
		t.pos += int64(n)
		t.mapBlocks++
		if err != nil {
			return fmt.Errorf("member %q: truncated sparse map: %w", name, err)
		}
		buf := append(carry, blk...)
		carry = nil
		for len(buf) > 0 {
			if buf[0] == 0 {
				complete = true // padding: the map's blocks end here
				break
			}
			nl := bytes.IndexByte(buf, '\n')
			if nl < 0 {
				carry = append([]byte{}, buf...) // continues in the next block
				break
			}
			v, err := strconv.ParseInt(string(buf[:nl]), 10, 64)
			if err != nil || v < 0 {
				return fmt.Errorf("member %q: malformed sparse map", name)
			}
			nums = append(nums, v)
			buf = buf[nl+1:]
			if want < 0 && len(nums) == 1 {
				if v > 1<<20 {
					return fmt.Errorf("member %q: sparse map claims %d extents", name, v)
				}
				want = int(v)
			}
			if want >= 0 && len(nums) == 1+2*want {
				complete = true
				break
			}
		}
		if n < blockSize {
			return fmt.Errorf("member %q: truncated sparse map", name)
		}
	}
	if want < 0 || len(nums) != 1+2*want {
		return fmt.Errorf("member %q: malformed sparse map", name)
	}
	spans := make([]member.SparseSpan, 0, want)
	for i := 0; i < want; i++ {
		spans = append(spans, member.SparseSpan{Off: nums[1+2*i], Len: nums[2+2*i]})
	}
	t.spans = spans
	return nil
}

// Read streams the current member's content.  For a sparse member it
// serves the extents' bytes tight, skipping the per-extent block
// padding as it goes.
func (t *Reader) Read(p []byte) (int, error) {
	if t.err != nil {
		return 0, t.err
	}
	if t.spans != nil {
		return t.readSparse(p)
	}
	if t.left <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > t.left {
		p = p[:t.left]
	}
	n, err := t.br.Read(p)
	t.left -= int64(n)
	if err == io.EOF {
		if t.left > 0 { // the stream ended inside the member's data
			return n, t.fail(io.ErrUnexpectedEOF)
		}
		if n > 0 {
			return n, nil
		}
		return 0, io.EOF
	}
	return n, err
}

// readSparse serves one read across the extent map: bytes from the
// current extent, then its block padding is skipped, then the next
// extent.  A zero-length extent (a trailing-hole marker) consumes
// nothing from the stream.
func (t *Reader) readSparse(p []byte) (int, error) {
	total := 0
	for total < len(p) {
		if t.spIdx >= len(t.spans) {
			if total > 0 {
				return total, nil
			}
			return 0, io.EOF
		}
		sp := t.spans[t.spIdx]
		if remain := sp.Len - t.spOff; remain > 0 {
			n := remain
			if avail := int64(len(p) - total); avail < n {
				n = avail
			}
			nn, err := io.ReadFull(t.br, p[total:total+int(n)])
			total += nn
			t.spOff += int64(nn)
			t.left -= int64(nn)
			t.pos += int64(nn)
			if err != nil {
				return total, t.fail(io.ErrUnexpectedEOF)
			}
			continue
		}
		// the extent is done: skip its padding to the next block
		if pad := int64(padUp(int(sp.Len), blockSize)) - sp.Len; pad > 0 {
			if _, err := io.CopyN(io.Discard, t.br, pad); err != nil {
				return total, t.fail(io.ErrUnexpectedEOF)
			}
			t.left -= pad
			t.pos += pad
		}
		t.spIdx++
		t.spOff = 0
	}
	return total, nil
}

// probeTrailing mimics the whole-buffer parse's trailing-garbage
// note: a short non-zero remainder after the end-of-archive marker is
// reported; a full block or more of trailing bytes was silently
// ignored there and still is.  Read errors end the probe quietly —
// the codec layer reports them where they matter.
func (t *Reader) probeTrailing() {
	rest := make([]byte, blockSize)
	n, _ := io.ReadFull(t.br, rest)
	t.pos += int64(n)
	if n > 0 && n < blockSize && !allZero(rest[:n]) {
		t.notes = append(t.notes, "trailing bytes after end-of-archive ignored")
	}
}

func (t *Reader) skipData() error {
	n := t.left + t.pad
	t.left, t.pad = 0, 0
	if n <= 0 {
		return nil
	}
	if _, err := io.CopyN(io.Discard, t.br, n); err != nil {
		return fmt.Errorf("truncated archive: %w", err)
	}
	return nil
}

// readInline reads one pseudo-member's content and its block padding.
func (t *Reader) readInline(name string, size int64) ([]byte, error) {
	if size > maxRecord {
		return nil, fmt.Errorf("member %q: extended record larger than %d bytes", name, maxRecord)
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(t.br, buf); err != nil {
		t.pos += size
		return nil, fmt.Errorf("truncated archive: member %q: %w", name, err)
	}
	t.pos += size
	t.discardPad(size)
	return buf, nil
}

// skipInline discards one pseudo-member's content and padding.
func (t *Reader) skipInline(name string, size int64) error {
	t.pos += size
	if _, err := io.CopyN(io.Discard, t.br, size); err != nil {
		return fmt.Errorf("truncated archive: member %q: %w", name, err)
	}
	t.discardPad(size)
	return nil
}

func (t *Reader) discardPad(size int64) {
	pad := int64(padUp(int(size), blockSize)) - size
	if pad > 0 {
		_, _ = io.CopyN(io.Discard, t.br, pad)
		t.pos += pad
	}
}

func (t *Reader) applyRecord(typeflag byte, data []byte) {
	switch typeflag {
	case 'x', 'X':
		recs, err := parsePaxRecords(data)
		if err != nil {
			t.notes = append(t.notes, err.Error())
			return
		}
		for k, v := range recs {
			// pax 0.0 repeats the sparse pair keys, which a map
			// collapses — collect them in order instead.
			switch k {
			case "GNU.sparse.offset":
				if n, err := strconv.ParseInt(v, 10, 64); err == nil {
					t.spOffs = append(t.spOffs, n)
				}
				continue
			case "GNU.sparse.numbytes":
				if n, err := strconv.ParseInt(v, 10, 64); err == nil {
					t.spLens = append(t.spLens, n)
				}
				continue
			}
			t.pending[k] = v
		}
		t.paxSeen = true
	case 'g':
		recs, err := parsePaxRecords(data)
		if err != nil {
			t.notes = append(t.notes, err.Error())
			return
		}
		for k, v := range recs {
			t.global[k] = v
		}
		t.paxSeen = true
	case 'L': // GNU long name
		t.pending["path"] = strings.TrimRight(string(data), "\x00")
	case 'K': // GNU long link name
		t.pending["linkpath"] = strings.TrimRight(string(data), "\x00")
	}
}

// readHdr is one decoded 512-byte header block.
type readHdr struct {
	name, linkname      string
	uname, gname, magic string
	mode, uid, gid      int64
	size, mtime         int64
	devmajor, devminor  int64
	typeflag            byte
	prefix              string

	// Old GNU sparse ('S') header fields: four map slots, the
	// extension flag, and the real (logical) file size.
	sparse    [4][2]int64
	sparseExt bool
	realsize  int64
	hasSparse bool
}

func decodeHeader(blk []byte) (h readHdr) {
	h.name = cstr(blk[0:100])
	h.mode = numeric(blk[100:108])
	h.uid = numeric(blk[108:116])
	h.gid = numeric(blk[116:124])
	h.size = numeric(blk[124:136])
	h.mtime = numeric(blk[136:148])
	h.typeflag = blk[156]
	h.linkname = cstr(blk[157:257])
	h.magic = string(blk[257:263])
	h.uname = cstr(blk[265:297])
	h.gname = cstr(blk[297:329])
	h.devmajor = numeric(blk[329:337])
	h.devminor = numeric(blk[337:345])
	if h.magic == "ustar\x00" {
		h.prefix = cstr(blk[345:500])
	}
	if h.typeflag == 'S' {
		h.hasSparse = true
		for i := 0; i < 4; i++ {
			h.sparse[i] = [2]int64{numeric(blk[386+24*i : 398+24*i]), numeric(blk[398+24*i : 410+24*i])}
		}
		h.sparseExt = blk[482] == '1'
		h.realsize = numeric(blk[483:495])
	}
	return h
}

// buildMember turns a header plus the accumulated pax/GNU records
// into a member, exactly as the whole-buffer parse did.
func (t *Reader) buildMember(h readHdr) (*member.Member, error) {
	rec := make(map[string]string, len(t.global)+len(t.pending))
	for k, v := range t.global {
		rec[k] = v
	}
	for k, v := range t.pending {
		rec[k] = v
	}
	t.pending = map[string]string{}

	m := member.Member{
		Mode:     uint32(h.mode & 0o7777),
		UID:      int(h.uid),
		GID:      int(h.gid),
		Uname:    h.uname,
		Gname:    h.gname,
		ModTime:  time.Unix(h.mtime, 0),
		DevMajor: uint32(h.devmajor),
		DevMinor: uint32(h.devminor),
	}
	full := h.name
	if h.prefix != "" {
		full = h.prefix + "/" + h.name
	}
	if p, ok := rec["path"]; ok {
		full = p
	}
	if ln, ok := rec["linkpath"]; ok {
		h.linkname = ln
	}
	a := &Archive{Variant: t.variant}
	full = cleanName(full, a)
	t.notes = append(t.notes, a.Notes...)
	m.Name = full
	m.LinkName = h.linkname

	switch h.typeflag {
	case '1':
		m.Kind = member.HardLink
	case '2':
		m.Kind = member.SymLink
		m.Data = []byte(h.linkname)
	case '3':
		m.Kind = member.CharDev
	case '4':
		m.Kind = member.BlockDev
	case '5':
		m.Kind = member.Directory
	case '6':
		m.Kind = member.FIFO
	default: // '0', '\0', '7', 'S', and anything unrecognized
		m.Kind = member.Regular
		if h.typeflag != '0' && h.typeflag != 0 && h.typeflag != '7' && h.typeflag != 'S' {
			t.notes = append(t.notes, fmt.Sprintf("unknown typeflag %q treated as a regular file", h.typeflag))
		}
	}

	// PAX numeric overrides.
	if v, ok := rec["uid"]; ok {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			m.UID = int(n)
		}
	}
	if v, ok := rec["gid"]; ok {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			m.GID = int(n)
		}
	}
	if v, ok := rec["uname"]; ok {
		m.Uname = v
	}
	if v, ok := rec["gname"]; ok {
		m.Gname = v
	}
	if v, ok := rec["mtime"]; ok {
		if sec, ns, ok := parsePaxTime(v); ok {
			m.ModTime = time.Unix(sec, ns)
		}
	}
	if v, ok := rec["size"]; ok {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n != h.size {
			t.notes = append(t.notes, fmt.Sprintf("member %q: pax size %d replaced by stored %d", full, n, h.size))
		}
	}

	if m.Kind == member.Regular || m.Kind == member.Directory {
		m.Size = h.size
	}

	// GNU sparse members.  The old-GNU 'S' header carries its map (and
	// the real size) directly; the pax flavors carry it in records —
	// version 1.0 defers the actual map to the member's first data
	// blocks, 0.0/0.1 repeat offset/numbytes pairs or give a comma
	// list.  GNU.sparse.size is the REAL size in 0.x records;
	// GNU.sparse.realsize is 1.0's.  The member header then holds a
	// dummy name (GNUSparseFile.N/…) that GNU.sparse.name overrides.
	paxMajor := false
	if v, ok := rec["GNU.sparse.major"]; ok {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			paxMajor = true
		}
	}
	recSparse := paxMajor ||
		rec["GNU.sparse.numblocks"] != "" ||
		rec["GNU.sparse.map"] != "" ||
		len(t.spOffs) > 0
	if h.hasSparse || recSparse {
		if !h.hasSparse {
			if n, ok := rec["GNU.sparse.name"]; ok && n != "" {
				a := &Archive{Variant: t.variant}
				full = cleanName(n, a)
				t.notes = append(t.notes, a.Notes...)
				m.Name = full
			}
		}
		m.Kind = member.Regular
		realsize := h.realsize
		if !h.hasSparse {
			realsize = h.size
			if v, ok := rec["GNU.sparse.realsize"]; ok {
				if n, err := strconv.ParseInt(v, 10, 64); err == nil {
					realsize = n
				}
			}
			if v, ok := rec["GNU.sparse.size"]; ok {
				if n, err := strconv.ParseInt(v, 10, 64); err == nil {
					realsize = n
				}
			}
		}
		m.Size = realsize
		if h.hasSparse {
			// spans were read from the 'S' header in Next
			t.sparseNext = true
		} else if paxMajor {
			t.sparseNext, t.sparsePending = true, true
		} else {
			spans, err := t.spansFromRecords(full)
			if err != nil {
				return nil, err
			}
			t.spans, t.sparseNext = spans, true
		}
		if err := validateSpans(full, t.spans, m.Size); err != nil {
			return nil, err
		}
		m.Sparse = t.spans
	}
	return &m, nil
}

// spansFromRecords builds the extent map for the pax 0.x flavors:
// GNU.sparse.map's flat comma list ("off,len,off,len,…"), or the
// ordered offset/numbytes record pairs applyRecord collected.
func (t *Reader) spansFromRecords(name string) ([]member.SparseSpan, error) {
	var spans []member.SparseSpan
	if s := t.pending["GNU.sparse.map"]; s != "" {
		parts := strings.Split(s, ",")
		if len(parts)%2 != 0 {
			return nil, fmt.Errorf("member %q: malformed sparse map", name)
		}
		for i := 0; i < len(parts); i += 2 {
			off, err1 := strconv.ParseInt(parts[i], 10, 64)
			num, err2 := strconv.ParseInt(parts[i+1], 10, 64)
			if err1 != nil || err2 != nil || off < 0 || num < 0 {
				return nil, fmt.Errorf("member %q: malformed sparse map", name)
			}
			spans = append(spans, member.SparseSpan{Off: off, Len: num})
		}
		return spans, nil
	}
	if len(t.spOffs) != len(t.spLens) || len(t.spOffs) == 0 {
		return nil, fmt.Errorf("member %q: malformed sparse records", name)
	}
	for i := range t.spOffs {
		spans = append(spans, member.SparseSpan{Off: t.spOffs[i], Len: t.spLens[i]})
	}
	return spans, nil
}

// parsePaxTime reads a pax timestamp — decimal seconds with an
// optional fraction — without float rounding (123456789 nanoseconds
// must survive the round trip).
func parsePaxTime(v string) (sec, ns int64, ok bool) {
	intPart, fracPart, hasFrac := strings.Cut(v, ".")
	sec, err := strconv.ParseInt(intPart, 10, 64)
	if err != nil {
		return 0, 0, false
	}
	if !hasFrac {
		return sec, 0, true
	}
	if len(fracPart) > 9 {
		fracPart = fracPart[:9]
	}
	for len(fracPart) < 9 {
		fracPart += "0"
	}
	ns, err = strconv.ParseInt(fracPart, 10, 64)
	if err != nil {
		return 0, 0, false
	}
	return sec, ns, true
}

// validateSpans applies GNU's sanity rules: non-negative, inside the
// logical file, and in order.
func validateSpans(name string, spans []member.SparseSpan, realsize int64) error {
	var end int64
	for _, s := range spans {
		if s.Off < 0 || s.Len < 0 || s.Off+s.Len > realsize || s.Off < end {
			return fmt.Errorf("member %q: invalid sparse archive member", name)
		}
		end = s.Off + s.Len
	}
	return nil
}

// cleanName strips the leading "/" GNU tar warns about and the
// trailing "/" of directory entries.  A leading "./" stays as stored:
// GNU tar, bsdtar, and cpio keep names relative to "." verbatim
// ("./f.txt"), so our own archives round-trip byte-stably.
func cleanName(name string, a *Archive) string {
	if strings.HasPrefix(name, "/") {
		a.Notes = append(a.Notes, fmt.Sprintf("member %q: stripping leading '/'", name))
		name = strings.TrimPrefix(name, "/")
	}
	return strings.TrimSuffix(name, "/")
}

func parsePaxRecords(data []byte) (map[string]string, error) {
	m := map[string]string{}
	for len(data) > 0 {
		sp := bytes.IndexByte(data, ' ')
		if sp < 0 {
			return m, fmt.Errorf("malformed pax record")
		}
		n, err := strconv.Atoi(string(data[:sp]))
		if err != nil || n <= sp+1 || n > len(data) {
			return m, fmt.Errorf("malformed pax record length")
		}
		rec := data[sp+1 : n-1] // strip the trailing '\n' at data[n-1]
		if kv := bytes.SplitN(rec, []byte("="), 2); len(kv) == 2 {
			m[string(kv[0])] = string(kv[1])
		}
		data = data[n:]
	}
	return m, nil
}

// errWriter is the write-side core: an io.Writer that remembers the
// first error and the byte count, so the block emitters below can
// ignore per-write errors and their callers check once.  It backs both
// the streaming Writer and the whole-buffer Build.
type errWriter struct {
	w   io.Writer
	n   int64
	err error
}

func (ew *errWriter) Write(p []byte) (int, error) {
	if ew.err != nil {
		return 0, ew.err
	}
	n, err := ew.w.Write(p)
	ew.n += int64(n)
	if err != nil {
		ew.err = err
	}
	return n, err
}

// write is Write for callers that track errors through ew.err (its
// return value carries nothing new).
func (ew *errWriter) write(p []byte) {
	_, _ = ew.Write(p)
}

// fail records err (first one wins), the Read-side fail pattern.
func (ew *errWriter) fail(err error) error {
	if ew.err == nil {
		ew.err = err
	}
	return ew.err
}

func (ew *errWriter) writeString(s string) {
	if ew.err != nil {
		return
	}
	var err error
	if sw, ok := ew.w.(io.StringWriter); ok {
		_, err = sw.WriteString(s)
	} else {
		_, err = ew.w.Write([]byte(s))
	}
	if err != nil {
		ew.err = err
	}
}

// Writer serializes members as a tar container one at a time, so an
// archive of any size can be written (through a compression layer, to
// a pipe) without materializing the container.  Build is the
// whole-buffer form and produces identical bytes.
type Writer struct {
	ew     errWriter
	format string
}

// NewWriter starts a tar stream in format ("gnu" default, "ustar",
// "pax", "v7") on w.
func NewWriter(w io.Writer, format string) (*Writer, error) {
	switch format {
	case "":
		format = "gnu"
	case "gnu", "ustar", "pax", "v7":
	default:
		return nil, fmt.Errorf("unknown tar format %q (want gnu, ustar, pax, or v7)", format)
	}
	return &Writer{ew: errWriter{w: w}, format: format}, nil
}

// WriteMember appends one member: extension records when the format
// and name need them, the header block, then the content padded to a
// block boundary.
func (t *Writer) WriteMember(m *member.Member) error {
	if t.ew.err != nil {
		return t.ew.err
	}
	if err := writeMember(&t.ew, t.format, m); err != nil {
		_ = t.ew.fail(err) // sticky, like an io error
		return err
	}
	return t.ew.err
}

// Close writes the end-of-archive marker: two zero blocks, padded to
// the traditional 20-block (10240-byte) record like GNU tar's default
// (an empty archive is still a full 10240-byte file).  It does not
// close the underlying writer.
func (t *Writer) Close() error {
	if t.ew.err != nil {
		return t.ew.err
	}
	t.ew.write(make([]byte, 2*blockSize))
	if extra := t.ew.n % (20 * blockSize); extra != 0 {
		t.ew.write(make([]byte, 20*blockSize-extra))
	}
	return t.ew.err
}

// Build serializes members as a tar container in memory.  format is
// "gnu" (default), "ustar", "pax", or "v7".
func Build(format string, mems []member.Member) ([]byte, error) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, format)
	if err != nil {
		return nil, err
	}
	for i := range mems {
		if err := w.WriteMember(&mems[i]); err != nil {
			return nil, err
		}
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// hdrSpec is one header block's worth of fields.
type hdrSpec struct {
	name, link, prefix          string
	mode, uid, gid, size, mtime int64
	typeflag                    byte
	uname, gname                string
	devmajor, devminor          int64
	base256                     bool // allow base-256 for big numbers

	// Old-GNU sparse ('S') additions: the first four extents, the
	// extension flag (implied by more than four), and the real size.
	sparse   bool
	spans    []member.SparseSpan
	realsize int64
}

func writeMember(w *errWriter, format string, m *member.Member) error {
	name := m.Name
	if m.Kind == member.Directory && !strings.HasSuffix(name, "/") {
		name += "/"
	}
	link := m.LinkName

	var paxPath, paxLink, paxMtime string
	needPax := false
	prefix, base := "", name

	switch format {
	case "gnu":
		if len(name) > 100 {
			writeGNURecord(w, 'L', name)
		}
		if len(link) > 100 {
			writeGNURecord(w, 'K', link)
		}
	case "v7":
		if len(name) > 100 || len(link) > 100 {
			return fmt.Errorf("member %q: v7 format cannot store names longer than 100 bytes", m.Name)
		}
	case "ustar", "pax":
		if len(name) > 100 {
			if format == "pax" {
				paxPath = name
				needPax = true
			} else {
				var err error
				prefix, base, err = splitUstar(name)
				if err != nil {
					return fmt.Errorf("member %q: %w", m.Name, err)
				}
			}
		}
		if len(link) > 100 {
			if format == "pax" {
				paxLink = link
				needPax = true
			} else {
				return fmt.Errorf("member %q: link name longer than 100 bytes (use --format=pax)", m.Name)
			}
		}
		if format == "pax" && m.ModTime.Nanosecond() != 0 {
			paxMtime = fmt.Sprintf("%d.%09d", m.ModTime.Unix(), m.ModTime.Nanosecond())
			needPax = true
		}
	}

	// pax numeric overflow records: the ustar fields hold 7 octal
	// digits for uid/gid and 11 for size; anything larger rides in
	// the extended header with zeros in the fields.
	var paxUID, paxGID, paxSize bool
	if format == "pax" {
		if int64(m.UID) > 0o7777777 {
			paxUID = true
			needPax = true
		}
		if int64(m.GID) > 0o7777777 {
			paxGID = true
			needPax = true
		}
		if m.Kind == member.Regular && m.Size > 0o77777777777 {
			paxSize = true
			needPax = true
		}
	}

	if m.Sparse != nil {
		if err := validateSpans(m.Name, m.Sparse, m.Size); err != nil {
			return err
		}
		var tight int64
		for _, sp := range m.Sparse {
			tight += sp.Len
		}
		if tight != int64(len(m.Data)) {
			return fmt.Errorf("member %q: sparse data is %d bytes but the extents claim %d", m.Name, len(m.Data), tight)
		}
		switch format {
		case "gnu":
			return writeSparseOldgnu(w, m)
		case "pax":
			needPax = true // the map records ride in the x header
		default:
			return fmt.Errorf("member %q: the %s format cannot store sparse members (use gnu or pax)", m.Name, format)
		}
	}

	if needPax {
		var recs bytes.Buffer
		if paxPath != "" {
			appendPaxRecord(&recs, "path", paxPath)
		}
		if paxLink != "" {
			appendPaxRecord(&recs, "linkpath", paxLink)
		}
		if paxMtime != "" {
			appendPaxRecord(&recs, "mtime", paxMtime)
		}
		if paxUID {
			appendPaxRecord(&recs, "uid", strconv.FormatInt(int64(m.UID), 10))
		}
		if paxGID {
			appendPaxRecord(&recs, "gid", strconv.FormatInt(int64(m.GID), 10))
		}
		if paxSize {
			appendPaxRecord(&recs, "size", strconv.FormatInt(m.Size, 10))
		}
		if m.Sparse != nil { // format == "pax" (checked above)
			appendPaxRecord(&recs, "GNU.sparse.major", "1")
			appendPaxRecord(&recs, "GNU.sparse.minor", "0")
			appendPaxRecord(&recs, "GNU.sparse.name", m.Name)
			appendPaxRecord(&recs, "GNU.sparse.realsize", strconv.FormatInt(m.Size, 10))
		}
		hdrName := "PaxHeaders.0/" + path.Base(name)
		if len(hdrName) > 100 {
			hdrName = hdrName[:100]
		}
		if err := writeHeader(w, format, hdrSpec{
			name: hdrName, mode: 0o644, size: int64(recs.Len()),
			typeflag: 'x', mtime: m.ModTime.Unix(), base256: true,
		}); err != nil {
			return err
		}
		w.write(recs.Bytes())
		padToBlock(w, recs.Len())
	}

	var typeflag byte = '0'
	switch m.Kind {
	case member.HardLink:
		typeflag = '1'
	case member.SymLink:
		typeflag = '2'
	case member.CharDev:
		typeflag = '3'
	case member.BlockDev:
		typeflag = '4'
	case member.Directory:
		typeflag = '5'
	case member.FIFO:
		typeflag = '6'
	}
	if len(base) > 100 {
		base = base[:100] // the L/K or pax record carries the full name
	}
	if len(link) > 100 {
		link = link[:100]
	}
	size := m.Size
	if m.Kind != member.Regular && m.Kind != member.Directory {
		size = 0
	}
	uid, gid := int64(m.UID), int64(m.GID)
	if paxUID {
		uid = 0
	}
	if paxGID {
		gid = 0
	}
	if paxSize {
		size = 0
	}
	if m.Sparse != nil { // pax 1.0: dummy name, map blocks + extents
		prefix, base = "", gnuSparseDummyName(name)
		size = int64(sparseMapBlocks(m))*blockSize + m.StoredSize()
		if len(base) > 100 {
			base = base[:100]
		}
	}
	err := writeHeader(w, format, hdrSpec{
		name: base, link: link, prefix: prefix,
		mode: int64(m.Mode & 0o7777), uid: uid, gid: gid,
		size: size, mtime: m.ModTime.Unix(), typeflag: typeflag,
		uname: m.Uname, gname: m.Gname,
		devmajor: int64(m.DevMajor), devminor: int64(m.DevMinor),
		base256: format == "gnu",
	})
	if err != nil {
		return err
	}
	if m.Sparse != nil {
		writeSparseMapBlock(w, m)
		writeSparseExtents(w, m)
		return w.err
	}
	if m.Kind == member.Regular && len(m.Data) > 0 {
		w.write(m.Data)
		padToBlock(w, len(m.Data))
	}
	return w.err
}

// writeSparseOldgnu writes an old-GNU sparse member: the 'S' header
// (four extents inline, realsize at 483, isextended when more follow),
// one extension sparse header per further 21 extents, then the extents
// each padded to a block.
func writeSparseOldgnu(w *errWriter, m *member.Member) error {
	name := m.Name
	if len(name) > 100 {
		name = name[:100] // the L record written above carries the rest
	}
	if err := writeHeader(w, "gnu", hdrSpec{
		name: name,
		mode: int64(m.Mode & 0o7777), uid: int64(m.UID), gid: int64(m.GID),
		size: m.StoredSize(), mtime: m.ModTime.Unix(), typeflag: 'S',
		uname: m.Uname, gname: m.Gname,
		devmajor: int64(m.DevMajor), devminor: int64(m.DevMinor),
		base256:  true,
		sparse:   true,
		spans:    m.Sparse,
		realsize: m.Size,
	}); err != nil {
		return err
	}
	rest := []member.SparseSpan(nil)
	if len(m.Sparse) > 4 {
		rest = m.Sparse[4:]
	}
	for i := 0; i < len(rest); i += 21 {
		n := len(rest) - i
		if n > 21 {
			n = 21
		}
		if err := writeSparseExtHeader(w, rest[i:i+n], len(rest)-i > 21); err != nil {
			return err
		}
	}
	writeSparseExtents(w, m)
	return w.err
}

// writeSparseExtHeader writes one old-GNU extension sparse header: 21
// extent slots from byte 0, isextended at 504.  GNU tar writes no
// checksum for these blocks — the slots run straight through the
// checksum's usual bytes — and its reader verifies none.
func writeSparseExtHeader(w *errWriter, spans []member.SparseSpan, more bool) error {
	var blk [blockSize]byte
	for i, sp := range spans {
		if err := putNum(blk[24*i:24*i+12], sp.Off, false); err != nil {
			return err
		}
		if err := putNum(blk[24*i+12:24*i+24], sp.Len, false); err != nil {
			return err
		}
	}
	if more {
		blk[504] = '1'
	}
	w.write(blk[:])
	return nil
}

// writeSparseExtents writes the member's extent bytes, each padded to
// a block — the stored form every GNU sparse flavor shares.  Zero-
// length extents (a trailing-hole marker) write nothing.
func writeSparseExtents(w *errWriter, m *member.Member) {
	pos := 0
	for _, sp := range m.Sparse {
		if sp.Len == 0 {
			continue
		}
		w.write(m.Data[pos : pos+int(sp.Len)])
		padToBlock(w, int(sp.Len))
		pos += int(sp.Len)
	}
}

// sparseMapString renders the pax 1.0 map: the extent count, then each
// offset and length, one decimal number per newline-terminated line.
func sparseMapString(m *member.Member) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d\n", len(m.Sparse))
	for _, sp := range m.Sparse {
		fmt.Fprintf(&b, "%d\n%d\n", sp.Off, sp.Len)
	}
	return b.String()
}

// sparseMapBlocks is how many 512-byte blocks the pax 1.0 map occupies
// (NUL-padded to a block boundary, like GNU writes it).
func sparseMapBlocks(m *member.Member) int {
	return padUp(len(sparseMapString(m)), blockSize) / blockSize
}

// writeSparseMapBlock writes the pax 1.0 map blocks ahead of the data.
func writeSparseMapBlock(w *errWriter, m *member.Member) {
	s := sparseMapString(m)
	w.writeString(s)
	padToBlock(w, len(s))
}

// gnuSparseDummyName is the placeholder a pax 1.0 sparse member's
// ustar header carries ("<dir>/GNUSparseFile.0/<base>"); the real name
// rides in the GNU.sparse.name record.
func gnuSparseDummyName(name string) string {
	i := strings.LastIndex(name, "/")
	if i < 0 {
		return "GNUSparseFile.0/" + name
	}
	return name[:i+1] + "GNUSparseFile.0/" + name[i+1:]
}

func writeHeader(w *errWriter, format string, s hdrSpec) error {
	// A zero time.Time (year 1) has a negative epoch; store 0.
	if s.mtime < 0 {
		s.mtime = 0
	}
	var blk [blockSize]byte
	copy(blk[0:100], s.name)
	if err := putNum(blk[100:108], s.mode, false); err != nil {
		return err
	}
	if err := putNum(blk[108:116], s.uid, s.base256); err != nil {
		return err
	}
	if err := putNum(blk[116:124], s.gid, s.base256); err != nil {
		return err
	}
	if err := putNum(blk[124:136], s.size, s.base256); err != nil {
		return err
	}
	if err := putNum(blk[136:148], s.mtime, s.base256); err != nil {
		return err
	}
	blk[156] = s.typeflag
	copy(blk[157:257], s.link)
	switch format {
	case "gnu":
		copy(blk[257:263], "ustar ")
		copy(blk[263:265], " \x00")
	case "ustar", "pax":
		copy(blk[257:263], "ustar\x00")
		copy(blk[263:265], "00")
	}
	copy(blk[265:297], s.uname)
	copy(blk[297:329], s.gname)
	if s.typeflag == '3' || s.typeflag == '4' {
		if err := putNum(blk[329:337], s.devmajor, false); err != nil {
			return err
		}
		if err := putNum(blk[337:345], s.devminor, false); err != nil {
			return err
		}
	}
	if format == "ustar" || format == "pax" {
		copy(blk[345:500], s.prefix)
	}
	if s.sparse {
		for i := 0; i < 4 && i < len(s.spans); i++ {
			if err := putNum(blk[386+24*i:398+24*i], s.spans[i].Off, false); err != nil {
				return err
			}
			if err := putNum(blk[398+24*i:410+24*i], s.spans[i].Len, false); err != nil {
				return err
			}
		}
		if len(s.spans) > 4 {
			blk[482] = '1'
		}
		if err := putNum(blk[483:495], s.realsize, false); err != nil {
			return err
		}
	}

	// Checksum: the byte sum of the block with the checksum field as
	// eight spaces, written as six octal digits, NUL, space.
	var sum int64
	for i := 0; i < blockSize; i++ {
		if i >= 148 && i < 156 {
			sum += ' '
		} else {
			sum += int64(blk[i])
		}
	}
	chk := fmt.Sprintf("%06o", sum)
	copy(blk[148:156], chk)
	blk[154] = 0
	blk[155] = ' '

	w.write(blk[:])
	return w.err
}

// writeGNURecord emits a GNU 'L' (long name) or 'K' (long link name)
// extension record.
func writeGNURecord(w *errWriter, typeflag byte, value string) {
	s := value + "\x00"
	_ = writeHeader(w, "gnu", hdrSpec{
		name: "././@LongLink", mode: 0o644, size: int64(len(s)),
		typeflag: typeflag,
	})
	w.writeString(s)
	padToBlock(w, len(s))
}

// appendPaxRecord writes one "length key=value\n" record, the length
// counting its own digits.
func appendPaxRecord(buf *bytes.Buffer, key, value string) {
	rec := key + "=" + value + "\n"
	for nd := 1; nd < 21; nd++ {
		total := nd + 1 + len(rec)
		if len(strconv.Itoa(total)) == nd {
			buf.WriteString(strconv.Itoa(total))
			buf.WriteByte(' ')
			buf.WriteString(rec)
			return
		}
	}
}

// splitUstar splits name into a 155-byte prefix and a 100-byte base,
// preferring the longest valid prefix.  The split lands on a '/'.
func splitUstar(name string) (prefix, base string, err error) {
	best := -1
	for i := 1; i < len(name); i++ {
		if name[i] != '/' {
			continue
		}
		if i <= 155 && len(name)-i-1 <= 100 {
			best = i
		}
	}
	if best < 0 {
		return "", "", fmt.Errorf("name longer than 100 bytes with no ustar prefix split (use --format=pax)")
	}
	return name[:best], name[best+1:], nil
}

// putNum writes v into the octal field f, zero-padded and NUL
// terminated; when v does not fit and big is set, GNU base-256 is
// used instead.
func putNum(f []byte, v int64, big bool) error {
	if v < 0 {
		return fmt.Errorf("tar header field cannot hold %d", v)
	}
	s := strconv.FormatInt(v, 8)
	if len(s) <= len(f)-1 {
		padded := strings.Repeat("0", len(f)-1-len(s)) + s
		copy(f, padded)
		f[len(f)-1] = 0 // NUL terminator
		return nil
	}
	if big {
		x := v
		for i := len(f) - 1; i >= 1; i-- {
			f[i] = byte(x)
			x >>= 8
		}
		f[0] = 0x80
		return nil
	}
	return fmt.Errorf("value %d does not fit the header field (use --format=pax)", v)
}

// numeric parses an octal tar field, honoring GNU base-256.
func numeric(f []byte) int64 {
	if len(f) > 0 && f[0]&0x80 != 0 {
		v := int64(f[0] & 0x7f)
		for _, c := range f[1:] {
			v = v<<8 | int64(c)
		}
		return v
	}
	s := strings.TrimFunc(string(f), func(r rune) bool { return r == ' ' || r == 0 })
	n, _ := strconv.ParseInt(s, 8, 64)
	return n
}

// cstr returns the NUL-terminated string in f.
func cstr(f []byte) string {
	if i := bytes.IndexByte(f, 0); i >= 0 {
		f = f[:i]
	}
	return string(f)
}

func padUp(n, bs int) int {
	return (n + bs - 1) &^ (bs - 1)
}

func padToBlock(w *errWriter, n int) {
	if r := n % blockSize; r != 0 {
		w.write(make([]byte, blockSize-r))
	}
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
