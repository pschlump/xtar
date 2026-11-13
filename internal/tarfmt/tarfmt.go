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
			if int64(len(data)) != m.Size {
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
			return nil, t.fail(fmt.Errorf("GNU sparse members are not supported yet (roadmap M4)"))
		}

		m, err := t.buildMember(h)
		if err != nil {
			return nil, t.fail(err)
		}
		t.left = h.size
		t.pad = int64(padUp(int(h.size), blockSize)) - h.size
		return m, nil
	}
}

// Read streams the current member's content.
func (t *Reader) Read(p []byte) (int, error) {
	if t.err != nil {
		return 0, t.err
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
		io.CopyN(io.Discard, t.br, pad)
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
	default: // '0', '\0', '7', and anything unrecognized
		m.Kind = member.Regular
		if h.typeflag != '0' && h.typeflag != 0 && h.typeflag != '7' {
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
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			sec := int64(f)
			m.ModTime = time.Unix(sec, int64((f-float64(sec))*1e9))
		}
	}
	if v, ok := rec["size"]; ok {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n != h.size {
			t.notes = append(t.notes, fmt.Sprintf("member %q: pax size %d replaced by stored %d", full, n, h.size))
		}
	}
	for k := range rec {
		if strings.HasPrefix(k, "GNU.sparse.") {
			return nil, fmt.Errorf("PAX sparse members are not supported yet (roadmap M4)")
		}
	}

	if m.Kind == member.Regular || m.Kind == member.Directory {
		m.Size = h.size
	}
	return &m, nil
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
	writeMember(&t.ew, t.format, m)
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
	t.ew.Write(make([]byte, 2*blockSize))
	if extra := t.ew.n % (20 * blockSize); extra != 0 {
		t.ew.Write(make([]byte, 20*blockSize-extra))
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
			paxMtime = strconv.FormatFloat(float64(m.ModTime.Unix())+float64(m.ModTime.Nanosecond())/1e9, 'g', 9, 64)
			needPax = true
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
		w.Write(recs.Bytes())
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
	err := writeHeader(w, format, hdrSpec{
		name: base, link: link, prefix: prefix,
		mode: int64(m.Mode & 0o7777), uid: int64(m.UID), gid: int64(m.GID),
		size: size, mtime: m.ModTime.Unix(), typeflag: typeflag,
		uname: m.Uname, gname: m.Gname,
		devmajor: int64(m.DevMajor), devminor: int64(m.DevMinor),
		base256: format == "gnu",
	})
	if err != nil {
		return err
	}
	if m.Kind == member.Regular && len(m.Data) > 0 {
		w.Write(m.Data)
		padToBlock(w, len(m.Data))
	}
	return w.err
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

	w.Write(blk[:])
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
		w.Write(make([]byte, blockSize-r))
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
