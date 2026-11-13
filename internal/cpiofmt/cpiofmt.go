/*
Copyright (C) Philip Schlump, 2012-2026.

BSD 3 Clause Licensed.
*/

// Package cpiofmt reads and writes the cpio container formats: SVR4
// "newc" (070701) and "crc" (070702), the portable octal "odc"
// (070707), and the legacy 16-bit "binary" (read only).  Members share
// the container-independent member.Member model.
package cpiofmt

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/pschlump/xtar/internal/member"
)

// Trailer is the end-of-archive member name.
const Trailer = "TRAILER!!!"

// Archive is a parsed cpio archive.
type Archive struct {
	Variant string // newc, crc, odc, binary, binary-swap
	Members []member.Member
	Notes   []string
}

// Parse decodes a cpio archive, auto-detecting the variant and
// loading every member's data: the whole-buffer form of the streaming
// Reader.
func Parse(b []byte) (*Archive, error) {
	r := NewReader(bytes.NewReader(b))
	var mems []member.Member
	for {
		m, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if m.Kind == member.Regular && m.Data == nil {
			data, err := io.ReadAll(r)
			if err != nil {
				return nil, err
			}
			if int64(len(data)) != m.Size {
				return nil, fmt.Errorf("cpio: member %s truncated", m.Name)
			}
			m.Data = data
		}
		mems = append(mems, *m)
	}
	if len(mems) == 0 && !r.SawTrailer() {
		return nil, fmt.Errorf("cpio: no members found")
	}
	return &Archive{Variant: r.Variant(), Members: mems, Notes: r.Notes()}, nil
}

// ------------------------------------------------------------------
// Streaming read side
// ------------------------------------------------------------------

// Reader decodes a cpio stream one member at a time: Next advances to
// the next member and Read streams the current member's content.  The
// variant is detected from the first header.  An archive of any size
// can be read through it (through a compression layer, from a pipe)
// without materializing the container.  Regular members arrive with
// Data unset; a symlink's Data carries its target, as Parse produces.
type Reader struct {
	br         *bufio.Reader
	pos        int64 // bytes consumed, for error messages
	variant    string
	variantSet bool
	left       int64 // data remaining for the current member
	pad        int64 // padding after it (variant-specific)
	seen       map[[2]uint64]string
	sum        uint32 // crc variant: running checksum of the current member
	wantSum    uint32
	checking   bool
	curName    string
	notes      []string
	sawTrailer bool
	eof        bool
	err        error
}

// NewReader starts decoding the cpio stream on r.
func NewReader(r io.Reader) *Reader {
	return &Reader{br: bufio.NewReaderSize(r, 128*1024), seen: map[[2]uint64]string{}}
}

// Variant reports the variant ("newc", "crc", "odc", "binary",
// "binary-swap"); "" until the first header.
func (c *Reader) Variant() string { return c.variant }

// Notes reports the non-fatal observations so far.
func (c *Reader) Notes() []string { return c.notes }

// SawTrailer reports whether the TRAILER!!! entry ended the archive
// (a stream that ends without one may be truncated).
func (c *Reader) SawTrailer() bool { return c.sawTrailer }

func (c *Reader) fail(err error) error {
	if c.err == nil {
		c.err = err
	}
	return c.err
}

// Next advances to the next member, discarding whatever is left of
// the current one's data.  io.EOF ends the archive.
func (c *Reader) Next() (*member.Member, error) {
	if c.err != nil {
		return nil, c.err
	}
	if c.eof {
		return nil, io.EOF
	}
	if err := c.finishMember(); err != nil {
		return nil, c.fail(err)
	}
	if !c.variantSet {
		if err := c.detect(); err != nil {
			return nil, c.fail(err)
		}
	}
	switch c.variant {
	case "newc", "crc":
		return c.nextNewc()
	case "odc":
		return c.nextOdc()
	default:
		return c.nextBinary()
	}
}

// Read streams the current member's content.
func (c *Reader) Read(p []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	if c.left <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.br.Read(p)
	c.left -= int64(n)
	if c.checking {
		for _, b := range p[:n] {
			c.sum += uint32(b)
		}
	}
	if err == io.EOF {
		if c.left > 0 { // the stream ended inside the member's data
			return n, c.fail(io.ErrUnexpectedEOF)
		}
		if n > 0 {
			return n, nil
		}
		return 0, io.EOF
	}
	return n, err
}

func (c *Reader) detect() error {
	head, _ := c.br.Peek(6)
	switch {
	case string(head) == "070701":
		c.variant = "newc"
	case string(head) == "070702":
		c.variant = "crc"
	case string(head) == "070707":
		c.variant = "odc"
	case len(head) >= 2 && head[0] == 0xc7 && head[1] == 0x71:
		c.variant = "binary"
	case len(head) >= 2 && head[0] == 0x71 && head[1] == 0xc7:
		c.variant = "binary-swap"
	default:
		return fmt.Errorf("not a cpio archive (no 070701/070702/070707 magic)")
	}
	c.variantSet = true
	if c.variant == "binary-swap" {
		c.notes = append(c.notes, "byte-swapped binary cpio detected")
	}
	return nil
}

// finishMember drains the current member's remaining data (adding it
// to the running checksum) and settles the crc comparison.
func (c *Reader) finishMember() error {
	rest := c.left + c.pad
	c.left, c.pad = 0, 0
	if rest > 0 {
		buf := make([]byte, 64*1024)
		for rest > 0 {
			n, err := c.br.Read(buf[:min(int64(len(buf)), rest)])
			if c.checking {
				for _, b := range buf[:n] {
					c.sum += uint32(b)
				}
			}
			rest -= int64(n)
			if err != nil {
				if err == io.EOF && rest >= 0 {
					break // the member is short; Next reports the state
				}
				return err
			}
			if n == 0 {
				break
			}
		}
	}
	if c.checking && c.sum != c.wantSum {
		c.notes = append(c.notes, fmt.Sprintf("%s: crc mismatch (stored %08x, computed %08x)", c.curName, c.wantSum, c.sum))
	}
	c.checking = false
	return nil
}

func (c *Reader) readName(namesize int64, at int64) (string, error) {
	if namesize < 1 {
		return "", fmt.Errorf("cpio: bad name size at offset %d", at)
	}
	buf := make([]byte, namesize)
	if _, err := io.ReadFull(c.br, buf); err != nil {
		return "", fmt.Errorf("cpio: truncated name at offset %d", at)
	}
	c.pos += namesize
	return strings.TrimRight(string(buf[:namesize-1]), "\x00"), nil
}

// discard skips n bytes (padding); running out is not an error, the
// next header read reports the real state.
func (c *Reader) discard(n int64) {
	io.CopyN(io.Discard, c.br, n)
	c.pos += n
}

// setMember applies the shared tail of every variant: identity fields
// from the header, the hard-link (dev, ino) resolution, and the
// streaming data position.
func (c *Reader) setMember(name string, mode uint64, uid, gid, nlink, ino, dev, mtime, rdevmaj, rdevmin uint64) (*member.Member, error) {
	var data []byte
	if mode&0o170000 == 0o120000 { // a symlink's target rides in its data section
		buf := make([]byte, c.left)
		if _, err := io.ReadFull(c.br, buf); err != nil {
			return nil, fmt.Errorf("cpio: member %s truncated", name)
		}
		if c.checking {
			for _, b := range buf {
				c.sum += uint32(b)
			}
		}
		c.pos += c.left
		c.left = 0
		data = buf
	}
	m := memberFromMode(name, mode, data)
	if data == nil {
		m.Size = c.left // data streams; the header size is authoritative
	}
	m.UID, m.GID = int(uid), int(gid)
	m.NLink = uint32(nlink)
	m.Ino, m.Dev = ino, dev
	m.ModTime = time.Unix(int64(mtime), 0)
	m.DevMajor = uint32(rdevmaj)
	m.DevMinor = uint32(rdevmin)
	if m.Kind == member.HardLink {
		if first, ok := c.seen[[2]uint64{dev, ino}]; ok {
			m.LinkName = first
		} else {
			m.Kind = member.Regular // dangling link: keep the data
		}
	}
	c.seen[[2]uint64{dev, ino}] = name
	c.curName = name
	return &m, nil
}

// nextNewc decodes one SVR4 ASCII-hex entry (newc and crc): 110-byte
// header, name including its NUL padded to 4, data padded to 4.
func (c *Reader) nextNewc() (*member.Member, error) {
	hdr := make([]byte, 110)
	n, err := io.ReadFull(c.br, hdr)
	c.pos += int64(n)
	if err != nil {
		c.missingTrailer()
		return nil, io.EOF
	}
	magic := "070701"
	if c.variant == "crc" {
		magic = "070702"
	}
	if string(hdr[:6]) != magic {
		return nil, c.fail(fmt.Errorf("cpio: bad magic at offset %d", c.pos-110))
	}
	var f [13]uint64
	for i := 0; i < 13; i++ {
		chunk := string(hdr[6+8*i : 6+8*(i+1)])
		if !isHex(chunk) {
			return nil, c.fail(fmt.Errorf("cpio: bad hex field at offset %d", c.pos-110))
		}
		v, err := strconv.ParseUint(chunk, 16, 64)
		if err != nil {
			return nil, c.fail(fmt.Errorf("cpio: bad hex field at offset %d", c.pos-110))
		}
		f[i] = v
	}
	ino, mode, uid, gid, nlink := f[0], f[1], f[2], f[3], f[4]
	mtime, filesize := f[5], f[6]
	devmaj, rdevmaj, rdevmin := f[7], f[9], f[10]
	namesize, check := f[11], f[12]
	name, err := c.readName(int64(namesize), c.pos)
	if err != nil {
		return nil, c.fail(err)
	}
	c.discard(int64(pad4(110 + int(namesize))))
	if name == Trailer {
		c.sawTrailer = true
		c.eof = true
		return nil, io.EOF
	}
	c.left = int64(filesize)
	c.pad = int64(pad4(int(filesize)))
	c.sum, c.checking = 0, c.variant == "crc" && check != 0
	c.wantSum = uint32(check)
	m, err := c.setMember(name, mode, uid, gid, nlink, ino, devmaj, mtime, rdevmaj, rdevmin)
	if err != nil {
		return nil, c.fail(err)
	}
	return m, nil
}

// nextOdc decodes one portable octal entry: 76-byte header, no
// padding anywhere.
func (c *Reader) nextOdc() (*member.Member, error) {
	hdr := make([]byte, 76)
	n, err := io.ReadFull(c.br, hdr)
	c.pos += int64(n)
	if err != nil {
		c.missingTrailer()
		return nil, io.EOF
	}
	if string(hdr[:6]) != "070707" {
		return nil, c.fail(fmt.Errorf("cpio: bad magic at offset %d", c.pos-76))
	}
	oct := func(off, n int) (uint64, error) {
		s := strings.Trim(strings.Trim(string(hdr[off:off+n]), "\x00"), " ")
		if s == "" {
			return 0, nil
		}
		v, err := strconv.ParseUint(s, 8, 64)
		if err != nil {
			return 0, fmt.Errorf("cpio: bad octal field %q at offset %d", s, c.pos-76+int64(off))
		}
		return v, nil
	}
	dev, err := oct(6, 6)
	if err != nil {
		return nil, c.fail(err)
	}
	ino, _ := oct(12, 6)
	mode, _ := oct(18, 6)
	uid, _ := oct(24, 6)
	gid, _ := oct(30, 6)
	nlink, _ := oct(36, 6)
	rdev, _ := oct(42, 6)
	mtime, _ := oct(48, 11)
	namesize, _ := oct(59, 6)
	filesize, err := oct(65, 11)
	if err != nil {
		return nil, c.fail(err)
	}
	name, err := c.readName(int64(namesize), c.pos)
	if err != nil {
		return nil, c.fail(err)
	}
	if name == Trailer {
		c.sawTrailer = true
		c.eof = true
		return nil, io.EOF
	}
	c.left = int64(filesize)
	c.pad = 0
	c.sum, c.checking, c.wantSum = 0, false, 0
	m, err := c.setMember(name, mode, uid, gid, nlink, ino, dev, mtime, rdev>>8, rdev&0xff)
	if err != nil {
		return nil, c.fail(err)
	}
	return m, nil
}

// nextBinary decodes one legacy 16-bit-word entry (read only; the
// swapped variant byte-swaps each word); names and data are padded to
// even length.
func (c *Reader) nextBinary() (*member.Member, error) {
	hdr := make([]byte, 26)
	n, err := io.ReadFull(c.br, hdr)
	c.pos += int64(n)
	if err != nil {
		c.missingTrailer()
		return nil, io.EOF
	}
	swapped := c.variant == "binary-swap"
	rd16 := func(off int) uint32 {
		lo, hi := hdr[off], hdr[off+1]
		if swapped {
			lo, hi = hi, lo
		}
		return uint32(hi)<<8 | uint32(lo)
	}
	rd32 := func(off int) uint32 { return rd16(off)<<16 | rd16(off+2) }
	if rd16(0) != 0o070707 {
		return nil, c.fail(fmt.Errorf("cpio: bad binary magic at offset %d", c.pos-26))
	}
	dev := uint64(rd16(2))
	ino := uint64(rd16(4))
	mode := uint64(rd16(6))
	uid := rd16(8)
	gid := rd16(10)
	nlink := rd16(12)
	rdev := rd16(14)
	mtime := rd32(16)
	namesize := rd16(20)
	filesize := rd32(22)
	name, err := c.readName(int64(namesize), c.pos)
	if err != nil {
		return nil, c.fail(err)
	}
	c.discard(int64(namesize & 1)) // names are padded to even length
	if name == Trailer {
		c.sawTrailer = true
		c.eof = true
		return nil, io.EOF
	}
	c.left = int64(filesize)
	c.pad = int64(filesize & 1) // data too, keeping 16-bit word alignment
	c.sum, c.checking, c.wantSum = 0, false, 0
	m, err := c.setMember(name, mode, uint64(uid), uint64(gid), uint64(nlink), ino, dev, uint64(mtime), uint64(rdev>>8), uint64(rdev&0xff))
	if err != nil {
		return nil, c.fail(err)
	}
	return m, nil
}

// missingTrailer notes an archive that ended without TRAILER!!!, the
// way the whole-buffer parse did.
func (c *Reader) missingTrailer() {
	c.notes = append(c.notes, "cpio: missing TRAILER!!! — archive may be truncated")
}

// memberFromMode maps a cpio mode word (type bits included) and data
// to a Member.
func memberFromMode(name string, mode uint64, data []byte) member.Member {
	m := member.Member{Name: name, Mode: uint32(mode & 0o7777)}
	switch mode & 0o170000 {
	case 0o040000:
		m.Kind = member.Directory
	case 0o120000:
		m.Kind = member.SymLink
		m.LinkName = string(data)
		m.Data = data
		m.Size = int64(len(data))
	case 0o010000:
		m.Kind = member.FIFO
	case 0o020000:
		m.Kind = member.CharDev
	case 0o060000:
		m.Kind = member.BlockDev
	default: // 0o100000 regular — or a 0-size link entry
		m.Kind = member.Regular
		if len(data) > 0 {
			m.Data = data
			m.Size = int64(len(data))
		} else {
			m.Kind = member.HardLink
		}
	}
	return m
}

func pad4(n int) int { return (4 - n%4) % 4 }

func isHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func checksum32(b []byte) uint32 {
	var sum uint32
	for _, c := range b {
		sum += uint32(c)
	}
	return sum
}

// ------------------------------------------------------------------
// Write side
// ------------------------------------------------------------------

// Writer serializes members as a cpio stream one at a time, so an
// archive of any size can be written (through a compression layer, to
// a pipe) without materializing the container.  Build is the
// whole-buffer form and produces identical bytes.  The (dev,ino)
// identity cpio link entries need is assigned as members arrive:
// real inodes where the members carry them, a stable synthetic number
// otherwise, and hard links sharing their target's — the same
// order-dependent assignment the whole-buffer writer made upfront.
type Writer struct {
	w       io.Writer
	err     error
	variant string
	ids     map[string]uint64 // member name -> assigned inode
	next    uint64            // synthetic inode counter
	remap   map[uint64]uint64 // odc: distinct identities -> 1..N
}

// NewWriter starts a cpio stream in variant ("newc", "crc", or "odc")
// on w.
func NewWriter(w io.Writer, variant string) (*Writer, error) {
	switch variant {
	case "newc", "crc", "odc":
	case "", "bin", "binary", "binary-swap":
		return nil, fmt.Errorf("cpio: the binary variant is read-only")
	default:
		return nil, fmt.Errorf("cpio: unknown format %q", variant)
	}
	return &Writer{
		w:       w,
		variant: variant,
		ids:     map[string]uint64{},
		remap:   map[uint64]uint64{},
	}, nil
}

func (c *Writer) write(p []byte) {
	if c.err != nil {
		return
	}
	if _, err := c.w.Write(p); err != nil {
		c.err = err
	}
}

// inode assigns m its cpio inode number.
func (c *Writer) inode(m *member.Member) uint64 {
	fresh := func() uint64 {
		c.next++
		return 90000 + c.next
	}
	ino := fresh()
	switch {
	case m.Ino != 0:
		ino = m.Ino
		if _, ok := c.ids[m.Name]; !ok {
			c.ids[m.Name] = m.Ino
		}
	case m.Kind == member.HardLink:
		if v, ok := c.ids[m.LinkName]; ok {
			ino = v
		}
	default:
		c.ids[m.Name] = ino
	}
	return ino
}

// WriteMember appends one member (header, name, data, padding).
func (c *Writer) WriteMember(m *member.Member) error {
	if c.err != nil {
		return c.err
	}
	data := m.Data
	if m.Kind == member.HardLink {
		data = nil
	}
	ino := c.inode(m)
	if c.variant == "odc" {
		// The 6-octal-digit fields cannot hold a modern inode number
		// (APFS inodes need 7+ digits, and %06o pads but never
		// truncates), so remap distinct identities to 1..N — link
		// families keep sharing.
		if _, ok := c.remap[ino]; !ok {
			c.remap[ino] = uint64(len(c.remap) + 1)
		}
		ino = c.remap[ino]
	}
	if err := c.writeEntry(ino, m, m.Name, data); err != nil {
		return err
	}
	return c.err
}

// Close writes the trailer entry.  It does not close the underlying
// writer.
func (c *Writer) Close() error {
	if c.err != nil {
		return c.err
	}
	if err := c.writeEntry(0, &member.Member{}, Trailer, nil); err != nil {
		return err
	}
	return c.err
}

func (c *Writer) writeEntry(ino uint64, m *member.Member, name string, data []byte) error {
	nlink := m.NLink
	if nlink < 1 {
		nlink = 1
	}
	if c.variant == "odc" {
		if uint64(mtimeOf(m)) > 0o77777777777 || uint64(len(data)) > 0o77777777777 {
			return fmt.Errorf("cpio: odc cannot hold %s (field overflow)", m.Name)
		}
		rdev := uint64(m.DevMajor)<<8 | uint64(m.DevMinor)
		oct := func(v uint64, n int) string { return fmt.Sprintf("%0*o", n, v) }
		c.write([]byte("070707"))
		for _, fld := range []struct {
			v uint64
			n int
		}{
			{0, 6}, {ino, 6}, {modeWord(m), 6},
			{uint64(uint32(m.UID)), 6}, {uint64(uint32(m.GID)), 6},
			{uint64(nlink), 6}, {rdev, 6},
			{uint64(mtimeOf(m)), 11},
			{uint64(len(name) + 1), 6}, {uint64(len(data)), 11},
		} {
			c.write([]byte(oct(fld.v, fld.n)))
		}
		c.write([]byte(name))
		c.write([]byte{0})
		c.write(data)
		return nil
	}
	magic := "070701"
	if c.variant == "crc" {
		magic = "070702"
	}
	var check uint64
	if c.variant == "crc" {
		check = uint64(checksum32(data))
	}
	f := func(v uint64) string { return fmt.Sprintf("%08x", v) }
	hdr := magic +
		f(ino) + f(modeWord(m)) + f(uint64(uint32(m.UID))) + f(uint64(uint32(m.GID))) +
		f(uint64(nlink)) + f(uint64(mtimeOf(m))) + f(uint64(len(data))) +
		f(0) + f(0) + // archive member's own device: unused on write
		f(uint64(m.DevMajor)) + f(uint64(m.DevMinor)) +
		f(uint64(len(name)+1)) + f(check)
	c.write([]byte(hdr))
	c.write([]byte(name))
	c.write([]byte{0})
	c.write(make([]byte, pad4(110+len(name)+1)))
	c.write(data)
	c.write(make([]byte, pad4(len(data))))
	return nil
}

// Build encodes mems in the given variant ("newc", "crc", or "odc").
func Build(variant string, mems []member.Member) ([]byte, error) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, variant)
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

// modeWord folds the kind into the UNIX mode word cpio stores.
func modeWord(m *member.Member) uint64 {
	return uint64(m.Mode&0o7777) | uint64(m.Kind.TypeBits())
}

func mtimeOf(m *member.Member) int64 {
	if m.ModTime.IsZero() {
		return 0
	}
	if t := m.ModTime.Unix(); t >= 0 {
		return t
	}
	return 0
}
