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

// Parse decodes a tar container from b.
func Parse(b []byte) (*Archive, error) {
	a := &Archive{Variant: "v7"}
	if len(b) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	pos := 0
	pending := map[string]string{} // pax/GNU records for the next member
	global := map[string]string{}
	variantSet := false
	paxSeen := false
	for {
		if pos+blockSize > len(b) {
			if pos < len(b) && !allZero(b[pos:]) {
				a.Notes = append(a.Notes, "trailing bytes after end-of-archive ignored")
			}
			break
		}
		blk := b[pos : pos+blockSize]
		if allZero(blk) {
			break // end-of-archive marker
		}
		if !sniff.HeaderChecksumOK(blk) {
			return nil, fmt.Errorf("header checksum mismatch at offset %d (this does not look like a tar archive)", pos)
		}
		name := cstr(blk[0:100])
		mode := numeric(blk[100:108])
		uid := numeric(blk[108:116])
		gid := numeric(blk[116:124])
		size := numeric(blk[124:136])
		mtime := numeric(blk[136:148])
		typeflag := blk[156]
		linkname := cstr(blk[157:257])
		magic := string(blk[257:263])
		uname := cstr(blk[265:297])
		gname := cstr(blk[297:329])
		devmajor := numeric(blk[329:337])
		devminor := numeric(blk[337:345])
		prefix := ""
		if magic == "ustar\x00" {
			prefix = cstr(blk[345:500])
		}
		if !variantSet {
			switch magic {
			case "ustar\x00":
				a.Variant = "ustar"
			case "ustar ":
				a.Variant = "gnu"
			default:
				a.Variant = "v7"
			}
			variantSet = true
		}
		if size < 0 || pos+blockSize+int(size) > len(b) {
			return nil, fmt.Errorf("truncated archive: member %q at offset %d", name, pos)
		}
		data := b[pos+blockSize : pos+blockSize+int(size)]
		pos += blockSize + padUp(int(size), blockSize)

		switch typeflag {
		case 'x', 'X':
			recs, err := parsePaxRecords(data)
			if err != nil {
				a.Notes = append(a.Notes, err.Error())
				continue
			}
			for k, v := range recs {
				pending[k] = v
			}
			paxSeen = true
			continue
		case 'g':
			recs, err := parsePaxRecords(data)
			if err != nil {
				a.Notes = append(a.Notes, err.Error())
				continue
			}
			for k, v := range recs {
				global[k] = v
			}
			paxSeen = true
			continue
		case 'L': // GNU long name
			pending["path"] = strings.TrimRight(string(data), "\x00")
			continue
		case 'K': // GNU long link name
			pending["linkpath"] = strings.TrimRight(string(data), "\x00")
			continue
		case 'V':
			a.Notes = append(a.Notes, "volume header ignored")
			continue
		case 'M':
			a.Notes = append(a.Notes, "multi-volume member skipped")
			continue
		case 'D':
			a.Notes = append(a.Notes, "dump directory entry ignored")
			continue
		case 'S':
			return nil, fmt.Errorf("GNU sparse members are not supported yet (roadmap M4)")
		}

		rec := make(map[string]string, len(global)+len(pending))
		for k, v := range global {
			rec[k] = v
		}
		for k, v := range pending {
			rec[k] = v
		}
		pending = map[string]string{}

		m := member.Member{
			Mode:     uint32(mode & 0o7777),
			UID:      int(uid),
			GID:      int(gid),
			Uname:    uname,
			Gname:    gname,
			ModTime:  time.Unix(mtime, 0),
			DevMajor: uint32(devmajor),
			DevMinor: uint32(devminor),
		}
		full := name
		if prefix != "" {
			full = prefix + "/" + name
		}
		if p, ok := rec["path"]; ok {
			full = p
		}
		if ln, ok := rec["linkpath"]; ok {
			linkname = ln
		}
		full = cleanName(full, a)
		m.Name = full
		m.LinkName = linkname

		switch typeflag {
		case '1':
			m.Kind = member.HardLink
		case '2':
			m.Kind = member.SymLink
			m.Data = []byte(linkname)
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
			if typeflag != '0' && typeflag != 0 && typeflag != '7' {
				a.Notes = append(a.Notes, fmt.Sprintf("unknown typeflag %q treated as a regular file", typeflag))
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
			if n, err := strconv.ParseInt(v, 10, 64); err == nil && n != int64(len(data)) {
				a.Notes = append(a.Notes, fmt.Sprintf("member %q: pax size %d replaced by stored %d", full, n, len(data)))
			}
		}
		for k := range rec {
			if strings.HasPrefix(k, "GNU.sparse.") {
				return nil, fmt.Errorf("PAX sparse members are not supported yet (roadmap M4)")
			}
		}

		if m.Kind == member.Regular || m.Kind == member.Directory {
			m.Data = data
			m.Size = int64(len(data))
		}
		a.Members = append(a.Members, m)
	}
	if paxSeen {
		a.Variant += "+pax"
	}
	return a, nil
}

// cleanName strips the "./" prefixes and leading "/" GNU tar warns
// about, and the trailing "/" of directory entries.
func cleanName(name string, a *Archive) string {
	for strings.HasPrefix(name, "./") {
		name = name[2:]
	}
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
