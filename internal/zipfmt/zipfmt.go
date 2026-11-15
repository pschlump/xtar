/*
Copyright (C) Philip Schlump, 2012-2026.

BSD 3 Clause Licensed.
*/

// Package zipfmt reads and writes the zip container: EOCD and central
// directory scanning, zip64 extensions, the store/deflate/bzip2
// methods, traditional PKWARE (ZipCrypto) encryption, CP437 name
// fallback, and enough verbatim state (member.ZipRaw) that update and
// delete rebuilds are lossless.  Compression itself comes from pluto.
package zipfmt

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/pschlump/pluto/bzip2"
	"github.com/pschlump/pluto/crc"
	"github.com/pschlump/pluto/deflate"
	"github.com/pschlump/xtar/internal/charset"
	"github.com/pschlump/xtar/internal/member"
)

// Method codes.
const (
	MethodStore   uint16 = 0
	MethodDeflate uint16 = 8
	MethodBZip2   uint16 = 12
)

// Flag bits.
const (
	flagEncrypted uint16 = 1 << 0
	flagDataDesc  uint16 = 1 << 3
	flagEFS       uint16 = 1 << 11
)

// decodeCP437 decodes legacy zip names (the spec fixes code page 437
// for entries without the UTF-8 flag).
var decodeCP437 = func() func([]byte) string {
	d, err := charset.ByName("cp437")
	if err != nil {
		panic(err)
	}
	return d
}()

// verMadeUNIX is the "made by" version for entries we write (UNIX,
// spec 2.0).
const verMadeUNIX = uint16(3)<<8 | 20

const max32 = uint64(0xFFFFFFFF)

var (
	sigLocal  = []byte("PK\x03\x04")
	sigCD     = []byte("PK\x01\x02")
	sigEOCD   = []byte("PK\x05\x06")
	sigZ64EOC = []byte("PK\x06\x06")
	sigZ64Loc = []byte("PK\x06\x07")
)

// zipCRCTab is the zip CRC-32 table (the same polynomial gzip uses).
var zipCRCTab = crc.MakeTable32(0xEDB88320)

// CRC32 computes the zip CRC of data.
func CRC32(data []byte) uint32 { return crc.Checksum32(data, zipCRCTab) }

// Archive is a parsed zip archive.
type Archive struct {
	Variant string // "" or "zip64"
	Comment string
	Members []member.Member
	Notes   []string
	Shift   int64 // bytes of prepended data before the archive proper (SFX stubs)
}

// Parse decodes a zip archive, decrypting with password when entries
// are encrypted ("" means none was supplied).
func Parse(b []byte, password string) (*Archive, error) {
	eocd := findEOCD(b)
	if eocd < 0 {
		return nil, fmt.Errorf("zip: no end-of-central-directory record")
	}
	a := &Archive{}
	le := binary.LittleEndian
	commentLen := int(le.Uint16(b[eocd+20:]))
	if eocd+22+commentLen > len(b) {
		return nil, fmt.Errorf("zip: truncated archive comment")
	}
	a.Comment = string(b[eocd+22 : eocd+22+commentLen])

	nEntries := int(le.Uint16(b[eocd+10:]))
	cdSize := int64(le.Uint32(b[eocd+12:]))
	cdOffset := int64(le.Uint32(b[eocd+16:]))
	// The central directory ends where the EOCD (and any zip64 records
	// in between) begins.
	cdEnd := int64(eocd)

	// zip64: any 0xFFFF/0xFFFFFFFF marker sends us to the zip64 EOCD.
	if nEntries == 0xFFFF || cdSize == int64(max32) || cdOffset == int64(max32) {
		z64, err := findZ64EOCD(b, eocd)
		if err != nil {
			return nil, err
		}
		nEntries = int(le.Uint64(b[z64+32:]))
		cdSize = int64(le.Uint64(b[z64+40:]))
		cdOffset = int64(le.Uint64(b[z64+48:]))
		a.Variant = "zip64"
		cdEnd = int64(z64)
	}

	// Prepended data (self-extracting stubs): all offsets the archive
	// carries are relative to the true zip start; detect the shift from
	// where the directory really sits.
	a.Shift = cdEnd - cdSize - cdOffset
	if a.Shift < 0 {
		// Some writers state a directory offset that is not absolute for
		// the bytes at hand (a split set's is relative to its last part).
		// The directory physically abuts the EOCD, so fall back to that.
		if alt := cdEnd - cdSize; alt >= 0 && alt+4 <= int64(len(b)) && bytes.Equal(b[alt:alt+4], sigCD) {
			a.Shift, cdOffset = 0, alt
			a.Notes = append(a.Notes, "central directory located by position: the stated offset did not match")
		} else {
			return nil, fmt.Errorf("zip: central directory offset %d is beyond the archive", cdOffset)
		}
	}
	cdStart := cdOffset + a.Shift

	var ents []*cdEntry
	pos := cdStart
	for i := 0; i < nEntries; i++ {
		if pos+46 > int64(len(b)) || !bytes.Equal(b[pos:pos+4], sigCD) {
			return nil, fmt.Errorf("zip: bad central directory record at offset %d", pos)
		}
		e := parseCDEntry(b, pos)
		if e == nil {
			return nil, fmt.Errorf("zip: truncated central directory entry at offset %d", pos)
		}
		pos = e.next
		ents = append(ents, e)
	}
	if fixed := fixLocalOffsets(b, ents, a.Shift, cdStart); fixed > 0 {
		a.Notes = append(a.Notes, fmt.Sprintf(
			"split or damaged archive: rebuilt %d of %d local header offsets by scanning", fixed, len(ents)))
	}
	for _, e := range ents {
		m, err := readMember(b, e, password, a.Shift)
		if err != nil {
			return nil, err
		}
		a.Members = append(a.Members, *m)
	}
	return a, nil
}

// fixLocalOffsets repairs local header offsets that do not point at a
// local header — the damage a concatenated split set carries, since
// split writers state each offset relative to its own part.  The
// repair is the zip -FF heuristic: local headers sit in the stream in
// the same order as their central-directory records, so the bytes
// before the directory are scanned for signatures and matched to
// records in order, each candidate verified against the record's
// stored name.  Stated offsets that already carry a local header are
// trusted.  It returns how many records were repaired.
func fixLocalOffsets(b []byte, ents []*cdEntry, shift, cdStart int64) int {
	broken := false
	for _, e := range ents {
		if !hasLocalSig(b, int64(e.offset)+shift) {
			broken = true
			break
		}
	}
	if !broken {
		return 0
	}
	fixed, cursor := 0, int64(0)
	for _, e := range ents {
		lh := int64(e.offset) + shift
		if hasLocalSig(b, lh) {
			cursor = lh + 1
			continue
		}
		p, ok := scanLocalHeader(b, cursor, cdStart, e.rawName)
		if !ok {
			continue // leave it be; readMember reports the offset it has
		}
		e.lhAbs = p
		cursor = p + 1
		fixed++
	}
	return fixed
}

// hasLocalSig reports whether pos carries a local file header signature.
func hasLocalSig(b []byte, pos int64) bool {
	return pos >= 0 && pos+4 <= int64(len(b)) && bytes.Equal(b[pos:pos+4], sigLocal)
}

// scanLocalHeader finds the next local header at or after from and
// before limit whose stored name is rawName.
func scanLocalHeader(b []byte, from, limit int64, rawName []byte) (int64, bool) {
	if limit > int64(len(b)) {
		limit = int64(len(b))
	}
	p := max(from, 0)
	for p+4 <= limit {
		i := int64(bytes.Index(b[p:limit], sigLocal))
		if i < 0 {
			return 0, false
		}
		p += i
		if p+30 <= int64(len(b)) {
			nlen := int64(binary.LittleEndian.Uint16(b[p+26:]))
			if p+30+nlen <= int64(len(b)) && bytes.Equal(b[p+30:p+30+nlen], rawName) {
				return p, true
			}
		}
		p += 4
	}
	return 0, false
}

func findEOCD(b []byte) int {
	// The EOCD is 22 bytes and carries at most a 64 KiB comment; scan
	// backward within that window.
	max := 22 + 65535
	if max > len(b) {
		max = len(b)
	}
	for i := len(b) - 22; i >= len(b)-max && i >= 0; i-- {
		if bytes.Equal(b[i:i+4], sigEOCD) {
			cl := int(binary.LittleEndian.Uint16(b[i+20:]))
			if i+22+cl <= len(b) {
				return i
			}
		}
	}
	return -1
}

// findZ64EOCD locates the zip64 EOCD record for an archive whose EOCD
// carries 0xFFFF/0xFFFFFFFF markers.  The locator sits directly before
// the EOCD; the record it points at is usually directly before the
// locator, but the pointed-at offset is relative to the true archive
// start (an SFX shift moves it), so also fall back to a scan.
func findZ64EOCD(b []byte, eocd int) (int, error) {
	loc := eocd - 20
	if loc < 0 || !bytes.Equal(b[loc:loc+4], sigZ64Loc) {
		return 0, fmt.Errorf("zip: zip64 markers without a zip64 locator")
	}
	if loc-56 >= 0 && bytes.Equal(b[loc-56:loc-52], sigZ64EOC) {
		return loc - 56, nil
	}
	off := int(binary.LittleEndian.Uint64(b[loc+8:]))
	if off+56 <= len(b) && bytes.Equal(b[off:off+4], sigZ64EOC) {
		return off, nil
	}
	if i := bytes.LastIndex(b[:loc], sigZ64EOC); i >= 0 && i+56 <= len(b) {
		return i, nil
	}
	return 0, fmt.Errorf("zip: zip64 locator does not point at a zip64 EOCD")
}

// cdEntry is one central-directory record, zip64 fields resolved.
type cdEntry struct {
	verMade, verNeed, flags, method uint16
	modTime, modDate                uint16
	crc                             uint32
	csize, usize                    uint64
	name                            string
	rawName                         []byte
	extra, comment                  []byte
	diskStart                       uint16
	internalAttr                    uint16
	externalAttr                    uint32
	offset                          uint64
	lhAbs                           int64 // absolute local header offset once repaired; -1 while stated
	next                            int64 // offset of the following record
}

func parseCDEntry(b []byte, pos int64) *cdEntry {
	le := binary.LittleEndian
	e := &cdEntry{
		verMade:      le.Uint16(b[pos+4:]),
		verNeed:      le.Uint16(b[pos+6:]),
		flags:        le.Uint16(b[pos+8:]),
		method:       le.Uint16(b[pos+10:]),
		modTime:      le.Uint16(b[pos+12:]),
		modDate:      le.Uint16(b[pos+14:]),
		crc:          le.Uint32(b[pos+16:]),
		csize:        uint64(le.Uint32(b[pos+20:])),
		usize:        uint64(le.Uint32(b[pos+24:])),
		diskStart:    le.Uint16(b[pos+34:]),
		internalAttr: le.Uint16(b[pos+36:]),
		externalAttr: le.Uint32(b[pos+38:]),
		offset:       uint64(le.Uint32(b[pos+42:])),
	}
	nameLen := int(le.Uint16(b[pos+28:]))
	extraLen := int(le.Uint16(b[pos+30:]))
	commentLen := int(le.Uint16(b[pos+32:]))
	if pos+46+int64(nameLen+extraLen+commentLen) > int64(len(b)) {
		return nil
	}
	e.rawName = b[pos+46 : pos+46+int64(nameLen)]
	e.extra = b[pos+46+int64(nameLen) : pos+46+int64(nameLen+extraLen)]
	e.comment = b[pos+46+int64(nameLen+extraLen) : pos+46+int64(nameLen+extraLen+commentLen)]
	e.next = pos + 46 + int64(nameLen+extraLen+commentLen)
	e.lhAbs = -1
	resolveZip64(e)
	return e
}

// resolveZip64 applies the zip64 extra fields that stand in for any
// 0xFFFF/0xFFFFFFFF marker (fields appear in a fixed order).
func resolveZip64(e *cdEntry) {
	if e.usize != max32 && e.csize != max32 && e.offset != max32 && e.diskStart != 0xFFFF {
		return
	}
	le := binary.LittleEndian
	for p := 0; p+4 <= len(e.extra); {
		id := le.Uint16(e.extra[p:])
		sz := int(le.Uint16(e.extra[p+2:]))
		if id != 1 || p+4+sz > len(e.extra) {
			p += 4 + sz
			continue
		}
		q := p + 4
		if e.usize == max32 && q+8 <= p+4+sz {
			e.usize = le.Uint64(e.extra[q:])
			q += 8
		}
		if e.csize == max32 && q+8 <= p+4+sz {
			e.csize = le.Uint64(e.extra[q:])
			q += 8
		}
		if e.offset == max32 && q+8 <= p+4+sz {
			e.offset = le.Uint64(e.extra[q:])
		}
		return
	}
}

// readMember follows one central-directory entry to its local header
// and payload and decodes it.  shift is the prepended-data offset
// added to every stored offset.
func readMember(b []byte, e *cdEntry, password string, shift int64) (*member.Member, error) {
	if e.flags&flagEFS != 0 {
		e.name = string(e.rawName)
	} else {
		e.name = decodeCP437(e.rawName)
	}

	lh := int64(e.offset) + shift
	if e.lhAbs >= 0 {
		lh = e.lhAbs
	}
	if lh < 0 || lh+30 > int64(len(b)) || !bytes.Equal(b[lh:lh+4], sigLocal) {
		return nil, fmt.Errorf("zip: member %s: bad local header at offset %d", e.name, lh)
	}
	le := binary.LittleEndian
	lNameLen := int(le.Uint16(b[lh+26:]))
	lExtraLen := int(le.Uint16(b[lh+28:]))
	dataStart := lh + 30 + int64(lNameLen) + int64(lExtraLen)
	if dataStart+int64(e.csize) > int64(len(b)) {
		return nil, fmt.Errorf("zip: member %s: payload is truncated", e.name)
	}
	payload := b[dataStart : dataStart+int64(e.csize)]

	m := &member.Member{
		Comment: string(e.comment),
		Method:  e.method,
	}
	m.Raw = &member.ZipRaw{
		RawName:      append([]byte(nil), e.rawName...), // for --encoding re-reads
		Method:       e.method,
		Flags:        e.flags &^ flagDataDesc, // rebuilt headers carry real sizes
		ModTime:      e.modTime,
		ModDate:      e.modDate,
		CRC:          e.crc,
		CompSize:     e.csize,
		UncompSize:   e.usize,
		Extra:        append([]byte(nil), b[lh+30+int64(lNameLen):dataStart]...),
		Data:         append([]byte(nil), payload...),
		Encrypted:    e.flags&flagEncrypted != 0,
		VersionMade:  e.verMade,
		InternalAttr: e.internalAttr,
		ExternalAttr: e.externalAttr,
		Comment:      string(e.comment),
	}

	data := payload
	if e.flags&flagEncrypted != 0 {
		if len(data) < 12 {
			return nil, fmt.Errorf("zip: member %s: encrypted payload too short", e.name)
		}
		if password == "" {
			return nil, fmt.Errorf("member %s is encrypted; a password is required (use -P)", e.name)
		}
		var ok bool
		data, ok = zipDecrypt(password, data, e.crc, e.flags)
		if !ok {
			return nil, fmt.Errorf("zip: member %s: wrong password", e.name)
		}
	}

	switch e.method {
	case MethodStore:
	case MethodDeflate:
		out, _ := deflate.Expand(data) // nil output is the error signal
		if out == nil {
			return nil, fmt.Errorf("zip: member %s: bad deflate stream", e.name)
		}
		data = out
	case MethodBZip2:
		out := bzip2.Expand(data)
		if out == nil && len(data) > 0 {
			return nil, fmt.Errorf("zip: member %s: bad bzip2 stream", e.name)
		}
		data = out
	default:
		return nil, fmt.Errorf("zip: member %s uses compression method %d, which is not supported", e.name, e.method)
	}

	if uint64(len(data)) != e.usize {
		return nil, fmt.Errorf("zip: member %s: size mismatch (stored %d, got %d)", e.name, e.usize, len(data))
	}
	if e.crc != 0 || len(data) > 0 {
		if sum := CRC32(data); sum != e.crc {
			return nil, fmt.Errorf("zip: member %s: CRC mismatch (stored %08x, computed %08x)", e.name, e.crc, sum)
		}
	}

	m.Name = e.name
	if n := m.Name; n != "" && n[len(n)-1] == '/' {
		m.Name = n[:len(n)-1]
		m.Kind = member.Directory
	}
	if e.verMade>>8 == 3 { // made on UNIX: external attrs carry a mode word
		unixMode := e.externalAttr >> 16
		m.Mode = unixMode & 0o7777
		switch unixMode & 0o170000 {
		case 0o120000:
			m.Kind = member.SymLink
			m.LinkName = string(data)
		case 0o040000:
			m.Kind = member.Directory
		case 0o020000:
			m.Kind = member.CharDev
		case 0o060000:
			m.Kind = member.BlockDev
		case 0o010000:
			m.Kind = member.FIFO
		case 0o100000:
			if m.Kind != member.Directory {
				m.Kind = member.Regular
			}
		}
	} else if m.Kind != member.Directory && e.externalAttr&0x10 != 0 {
		m.Kind = member.Directory // DOS directory bit
	}
	if m.Mode == 0 {
		if m.Kind == member.Directory {
			m.Mode = 0o755
		} else {
			m.Mode = 0o644
		}
	}
	m.ModTime = dosTime(e.modDate, e.modTime)
	if m.Kind == member.Directory {
		m.Data, m.Size = nil, 0
	} else {
		m.Data, m.Size = data, int64(len(data))
	}
	return m, nil
}

// ------------------------------------------------------------------
// Write side
// ------------------------------------------------------------------

// Build encodes mems as a zip archive.  Members whose ZipRaw is set
// and KeepStored is true are rewritten verbatim — compressed bytes
// untouched, so encrypted entries stay encrypted without needing the
// password.  Fresh members with Encrypted set are ZipCrypto-encrypted
// with password.
func Build(mems []member.Member, comment, password string) ([]byte, error) {
	var out bytes.Buffer
	offsets := make([]uint64, len(mems))

	type cdInfo struct {
		flags, method uint16
		dtime, ddate  uint16
		crc           uint32
		usize, csize  uint64
		verMade       uint16
		external      uint32
		comment       string
	}
	cds := make([]cdInfo, len(mems))

	for i := range mems {
		m := &mems[i]
		// Zip marks directories by a trailing slash in the stored name.
		if m.Kind == member.Directory && len(m.Name) > 0 && m.Name[len(m.Name)-1] != '/' {
			m.Name += "/"
		}
		var payload []byte
		var info cdInfo

		if m.Raw != nil && m.KeepStored {
			r := m.Raw
			payload = r.Data
			info = cdInfo{
				flags:    r.Flags,
				method:   r.Method,
				dtime:    r.ModTime,
				ddate:    r.ModDate,
				crc:      r.CRC,
				usize:    r.UncompSize,
				csize:    uint64(len(payload)),
				verMade:  r.VersionMade,
				external: r.ExternalAttr,
				comment:  r.Comment,
			}
		} else {
			data := m.Data
			if m.Kind == member.SymLink {
				data = []byte(m.LinkName)
			}
			if m.Kind == member.Directory {
				data = nil
			}
			csum := CRC32(data)
			dtime, ddate := toDOS(m.ModTime)
			method := m.Method // 0 = store; callers pick the default
			comp := data
			switch method {
			case MethodStore:
			case MethodDeflate:
				comp = deflate.Compress(data)
				if len(comp) >= len(data) { // deflate that grows is pointless
					method, comp = MethodStore, data
				}
			case MethodBZip2:
				comp = bzip2.Compress(data)
			default:
				return nil, fmt.Errorf("zip: %s: method %d is not writable", m.Name, method)
			}
			flags := uint16(0)
			if !isASCII(m.Name) {
				flags |= flagEFS
			}
			if m.Encrypted {
				if password == "" {
					return nil, fmt.Errorf("zip: %s: encryption requested but no password was given", m.Name)
				}
				flags |= flagEncrypted
				comp = zipEncrypt(password, comp, byte(csum>>24))
			}
			payload = comp
			// The UNIX mode word (type bits included) lives in the
			// high half of the external attributes.
			external := (m.Mode | m.Kind.TypeBits()) << 16
			if m.Kind == member.Directory {
				external |= 0x10 // DOS directory bit for non-UNIX readers
			}
			info = cdInfo{
				flags:    flags,
				method:   method,
				dtime:    dtime,
				ddate:    ddate,
				crc:      csum,
				usize:    uint64(len(data)),
				csize:    uint64(len(comp)),
				verMade:  verMadeUNIX,
				external: external,
				comment:  m.Comment,
			}
		}
		cds[i] = info

		// Local file header.
		offsets[i] = uint64(out.Len())
		var lextra []byte
		sz32 := func(v uint64) uint32 {
			if v > max32 {
				return uint32(max32)
			}
			return uint32(v)
		}
		if info.usize > max32 || info.csize > max32 {
			lextra = zip64Extra(info.usize, info.csize, 0)
		}
		hdr := make([]byte, 30)
		binary.LittleEndian.PutUint16(hdr[4:], 20)
		binary.LittleEndian.PutUint16(hdr[6:], info.flags)
		binary.LittleEndian.PutUint16(hdr[8:], info.method)
		binary.LittleEndian.PutUint16(hdr[10:], info.dtime)
		binary.LittleEndian.PutUint16(hdr[12:], info.ddate)
		binary.LittleEndian.PutUint32(hdr[14:], info.crc)
		binary.LittleEndian.PutUint32(hdr[18:], sz32(info.csize))
		binary.LittleEndian.PutUint32(hdr[22:], sz32(info.usize))
		binary.LittleEndian.PutUint16(hdr[26:], uint16(len(m.Name)))
		binary.LittleEndian.PutUint16(hdr[28:], uint16(len(lextra)))
		copy(hdr[:4], sigLocal)
		out.Write(hdr)
		out.WriteString(m.Name)
		out.Write(lextra)
		out.Write(payload)
	}

	// Central directory.
	cdStart := uint64(out.Len())
	le := binary.LittleEndian
	for i := range mems {
		info := cds[i]
		var oextra []byte
		if info.usize > max32 || info.csize > max32 || offsets[i] > max32 {
			oextra = zip64Extra(info.usize, info.csize, offsets[i])
		}
		sz32 := func(v uint64) uint32 {
			if v > max32 {
				return uint32(max32)
			}
			return uint32(v)
		}
		hdr := make([]byte, 46)
		le.PutUint16(hdr[4:], info.verMade)
		le.PutUint16(hdr[6:], 20)
		le.PutUint16(hdr[8:], info.flags)
		le.PutUint16(hdr[10:], info.method)
		le.PutUint16(hdr[12:], info.dtime)
		le.PutUint16(hdr[14:], info.ddate)
		le.PutUint32(hdr[16:], info.crc)
		le.PutUint32(hdr[20:], sz32(info.csize))
		le.PutUint32(hdr[24:], sz32(info.usize))
		le.PutUint16(hdr[28:], uint16(len(mems[i].Name)))
		le.PutUint16(hdr[30:], uint16(len(oextra)))
		le.PutUint16(hdr[32:], uint16(len(info.comment)))
		le.PutUint32(hdr[38:], info.external)
		le.PutUint32(hdr[42:], sz32(offsets[i]))
		copy(hdr[:4], sigCD)
		out.Write(hdr)
		out.WriteString(mems[i].Name)
		out.Write(oextra)
		out.WriteString(info.comment)
	}
	cdSize := uint64(out.Len()) - cdStart

	// zip64 EOCD + locator when any 32-bit field would overflow.
	n := uint64(len(mems))
	needZ64 := n > 0xFFFF || cdSize > max32 || cdStart > max32
	if needZ64 {
		z := make([]byte, 56)
		copy(z[:4], sigZ64EOC)
		le.PutUint64(z[4:], 44)
		le.PutUint16(z[8:], verMadeUNIX)
		le.PutUint16(z[10:], 45)
		le.PutUint64(z[24:], n)
		le.PutUint64(z[32:], n)
		le.PutUint64(z[40:], cdSize)
		le.PutUint64(z[48:], cdStart)
		out.Write(z)
		loc := make([]byte, 20)
		copy(loc[:4], sigZ64Loc)
		le.PutUint64(loc[8:], cdStart+cdSize)
		le.PutUint32(loc[16:], 1)
		out.Write(loc)
	}

	e := make([]byte, 22)
	copy(e[:4], sigEOCD)
	if !needZ64 {
		le.PutUint16(e[8:], uint16(n))  // entries on this disk
		le.PutUint16(e[10:], uint16(n)) // entries in total
		le.PutUint32(e[12:], uint32(cdSize))
		le.PutUint32(e[16:], uint32(cdStart))
	} else {
		le.PutUint16(e[8:], 0xFFFF)
		le.PutUint16(e[10:], 0xFFFF)
		le.PutUint32(e[12:], uint32(max32))
		le.PutUint32(e[16:], uint32(max32))
	}
	le.PutUint16(e[20:], uint16(len(comment)))
	out.Write(e)
	out.WriteString(comment)
	return out.Bytes(), nil
}

// zip64Extra builds the 0x0001 extra record, including each field
// whose value overflows 32 bits (order fixed by the spec).
func zip64Extra(usize, csize, offset uint64) []byte {
	var body []byte
	le := binary.LittleEndian
	add := func(v uint64, needed bool) {
		if !needed {
			return
		}
		b := make([]byte, 8)
		le.PutUint64(b, v)
		body = append(body, b...)
	}
	add(usize, usize > max32)
	add(csize, csize > max32)
	add(offset, offset > max32)
	out := make([]byte, 4+len(body))
	le.PutUint16(out, 1)
	le.PutUint16(out[2:], uint16(len(body)))
	copy(out[4:], body)
	return out
}

// dosTime converts a DOS date/time pair (local time, 2-second
// granularity) to a time.Time.
func dosTime(d, t uint16) time.Time {
	sec := int(t&0x1f) * 2
	min := int(t>>5) & 0x3f
	hour := int(t>>11) & 0x1f
	day := int(d & 0x1f)
	mon := int(d>>5) & 0x0f
	year := 1980 + int(d>>9)
	if mon < 1 || mon > 12 || day < 1 || day > 31 {
		return time.Time{}
	}
	return time.Date(year, time.Month(mon), day, hour, min, sec, 0, time.Local)
}

// toDOS converts a time to the DOS date/time pair, clamping to the
// representable range (1980 through 2107).
func toDOS(t time.Time) (uint16, uint16) {
	if t.IsZero() {
		t = time.Unix(0, 0)
	}
	y := t.Year()
	if y < 1980 {
		return 0, 1 << 5 // 1980-01-01 00:00:00
	}
	if y > 2107 {
		return (23 << 11) | (59 << 5) | 29, (12 << 5) | 31 | ((2107 - 1980) << 9)
	}
	d := uint16(t.Day() | int(t.Month())<<5 | (y-1980)<<9)
	tt := uint16(t.Second()/2 | t.Minute()<<5 | t.Hour()<<11)
	return tt, d
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}
