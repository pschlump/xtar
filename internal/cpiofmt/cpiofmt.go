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
	"fmt"
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

// Parse decodes a cpio archive, auto-detecting the variant.
func Parse(b []byte) (*Archive, error) {
	var v string
	switch {
	case hasMagic(b, "070701"):
		v = "newc"
	case hasMagic(b, "070702"):
		v = "crc"
	case hasMagic(b, "070707"):
		v = "odc"
	case len(b) >= 2 && b[0] == 0xc7 && b[1] == 0x71:
		v = "binary"
	case len(b) >= 2 && b[0] == 0x71 && b[1] == 0xc7:
		v = "binary-swap"
	default:
		return nil, fmt.Errorf("not a cpio archive (no 070701/070702/070707 magic)")
	}
	switch v {
	case "newc", "crc":
		return parseNewc(b, v)
	case "odc":
		return parseOdc(b)
	default:
		return parseBinary(b, v == "binary-swap")
	}
}

func hasMagic(b []byte, m string) bool {
	return len(b) >= len(m) && string(b[:len(m)]) == m
}

// parseNewc decodes the SVR4 ASCII-hex formats.  Layout: 110-byte
// header, name including its NUL, pad to 4; data, pad to 4.
func parseNewc(b []byte, variant string) (*Archive, error) {
	a := &Archive{Variant: variant}
	magic := "070701"
	if variant == "crc" {
		magic = "070702"
	}
	pos := 0
	type linkKey struct{ dev, ino uint64 }
	seen := map[linkKey]string{}
	for pos+110 <= len(b) {
		if string(b[pos:pos+6]) != magic {
			return nil, fmt.Errorf("cpio: bad magic at offset %d", pos)
		}
		var f [13]uint64
		for i := 0; i < 13; i++ {
			chunk := string(b[pos+6+8*i : pos+6+8*(i+1)])
			if !isHex(chunk) {
				return nil, fmt.Errorf("cpio: bad hex field at offset %d", pos)
			}
			v, err := strconv.ParseUint(chunk, 16, 64)
			if err != nil {
				return nil, fmt.Errorf("cpio: bad hex field at offset %d", pos)
			}
			f[i] = v
		}
		ino, mode, uid, gid, nlink := f[0], f[1], f[2], f[3], f[4]
		mtime, filesize := f[5], f[6]
		devmaj, rdevmaj, rdevmin := f[7], f[9], f[10]
		namesize, check := f[11], f[12]
		pos += 110
		if namesize < 1 || pos+int(namesize) > len(b) {
			return nil, fmt.Errorf("cpio: truncated name at offset %d", pos)
		}
		name := strings.TrimRight(string(b[pos:pos+int(namesize)-1]), "\x00")
		pos += int(namesize)
		pos += pad4(110 + int(namesize))
		if name == Trailer {
			return a, nil
		}
		if pos+int(filesize) > len(b) {
			return nil, fmt.Errorf("cpio: member %s truncated", name)
		}
		data := b[pos : pos+int(filesize)]
		pos += int(filesize)
		pos += pad4(int(filesize))

		if variant == "crc" && check != 0 {
			if sum := checksum32(data); uint64(sum) != check {
				a.Notes = append(a.Notes, fmt.Sprintf("%s: crc mismatch (stored %08x, computed %08x)", name, check, sum))
			}
		}

		m := memberFromMode(name, mode, data)
		m.UID, m.GID = int(uid), int(gid)
		m.NLink = uint32(nlink)
		m.Ino, m.Dev = ino, devmaj
		m.ModTime = time.Unix(int64(mtime), 0)
		m.DevMajor = uint32(rdevmaj)
		m.DevMinor = uint32(rdevmin)
		if m.Kind == member.HardLink {
			if first, ok := seen[linkKey{devmaj, ino}]; ok {
				m.LinkName = first
			} else {
				m.Kind = member.Regular // dangling link: keep the data
			}
		}
		seen[linkKey{devmaj, ino}] = name
		a.Members = append(a.Members, m)
	}
	if len(a.Members) == 0 {
		return nil, fmt.Errorf("cpio: no members found")
	}
	a.Notes = append(a.Notes, "cpio: missing TRAILER!!! — archive may be truncated")
	return a, nil
}

// parseOdc decodes the portable octal format: 76-byte headers, no
// padding anywhere.
func parseOdc(b []byte) (*Archive, error) {
	a := &Archive{Variant: "odc"}
	pos := 0
	type linkKey struct{ dev, ino uint64 }
	seen := map[linkKey]string{}
	oct := func(off, n int) (uint64, error) {
		if off+n > len(b) {
			return 0, fmt.Errorf("cpio: truncated odc header at %d", pos)
		}
		s := strings.Trim(strings.Trim(string(b[off:off+n]), "\x00"), " ")
		if s == "" {
			return 0, nil
		}
		v, err := strconv.ParseUint(s, 8, 64)
		if err != nil {
			return 0, fmt.Errorf("cpio: bad octal field %q at offset %d", s, off)
		}
		return v, nil
	}
	for pos+76 <= len(b) {
		if string(b[pos:pos+6]) != "070707" {
			return nil, fmt.Errorf("cpio: bad magic at offset %d", pos)
		}
		dev, err := oct(pos+6, 6)
		if err != nil {
			return nil, err
		}
		ino, _ := oct(pos+12, 6)
		mode, _ := oct(pos+18, 6)
		uid, _ := oct(pos+24, 6)
		gid, _ := oct(pos+30, 6)
		nlink, _ := oct(pos+36, 6)
		rdev, _ := oct(pos+42, 6)
		mtime, _ := oct(pos+48, 11)
		namesize, _ := oct(pos+59, 6)
		filesize, err := oct(pos+65, 11)
		if err != nil {
			return nil, err
		}
		pos += 76
		if namesize < 1 || pos+int(namesize) > len(b) {
			return nil, fmt.Errorf("cpio: truncated name at offset %d", pos)
		}
		name := strings.TrimRight(string(b[pos:pos+int(namesize)-1]), "\x00")
		pos += int(namesize)
		if name == Trailer {
			return a, nil
		}
		if pos+int(filesize) > len(b) {
			return nil, fmt.Errorf("cpio: member %s truncated", name)
		}
		data := b[pos : pos+int(filesize)]
		pos += int(filesize)

		m := memberFromMode(name, mode, data)
		m.UID, m.GID = int(uid), int(gid)
		m.NLink = uint32(nlink)
		m.Ino, m.Dev = ino, dev
		m.ModTime = time.Unix(int64(mtime), 0)
		m.DevMajor = uint32(rdev >> 8)
		m.DevMinor = uint32(rdev & 0xff)
		if m.Kind == member.HardLink {
			if first, ok := seen[linkKey{dev, ino}]; ok {
				m.LinkName = first
			} else {
				m.Kind = member.Regular
			}
		}
		seen[linkKey{dev, ino}] = name
		a.Members = append(a.Members, m)
	}
	if len(a.Members) == 0 {
		return nil, fmt.Errorf("cpio: no members found")
	}
	a.Notes = append(a.Notes, "cpio: missing TRAILER!!! — archive may be truncated")
	return a, nil
}

// parseBinary decodes the legacy 16-bit-word format (read only; the
// swapped variant byte-swaps each word).
func parseBinary(b []byte, swapped bool) (*Archive, error) {
	a := &Archive{Variant: "binary"}
	if swapped {
		a.Variant = "binary-swap"
		a.Notes = append(a.Notes, "byte-swapped binary cpio detected")
	}
	rd16 := func(off int) uint32 {
		lo, hi := b[off], b[off+1]
		if swapped {
			lo, hi = hi, lo
		}
		return uint32(hi)<<8 | uint32(lo)
	}
	rd32 := func(off int) uint32 { return rd16(off)<<16 | rd16(off+2) }
	pos := 0
	type linkKey struct{ dev, ino uint64 }
	seen := map[linkKey]string{}
	for pos+26 <= len(b) {
		if rd16(pos) != 0o070707 {
			return nil, fmt.Errorf("cpio: bad binary magic at offset %d", pos)
		}
		dev := uint64(rd16(pos + 2))
		ino := uint64(rd16(pos + 4))
		mode := uint64(rd16(pos + 6))
		uid := rd16(pos + 8)
		gid := rd16(pos + 10)
		nlink := rd16(pos + 12)
		rdev := rd16(pos + 14)
		mtime := rd32(pos + 16)
		namesize := rd16(pos + 20)
		filesize := rd32(pos + 22)
		pos += 26
		if namesize < 1 || pos+int(namesize) > len(b) {
			return nil, fmt.Errorf("cpio: truncated name at offset %d", pos)
		}
		name := strings.TrimRight(string(b[pos:pos+int(namesize)-1]), "\x00")
		pos += int(namesize)
		pos += int(namesize & 1) // names are padded to even length
		if name == Trailer {
			return a, nil
		}
		if pos+int(filesize) > len(b) {
			return nil, fmt.Errorf("cpio: member %s truncated", name)
		}
		data := b[pos : pos+int(filesize)]
		pos += int(filesize)
		pos += int(filesize & 1) // data too, keeping 16-bit word alignment

		m := memberFromMode(name, mode, data)
		m.UID, m.GID = int(uid), int(gid)
		m.NLink = nlink
		m.Ino, m.Dev = ino, dev
		m.ModTime = time.Unix(int64(mtime), 0)
		m.DevMajor = rdev >> 8
		m.DevMinor = rdev & 0xff
		if m.Kind == member.HardLink {
			if first, ok := seen[linkKey{dev, ino}]; ok {
				m.LinkName = first
			} else {
				m.Kind = member.Regular
			}
		}
		seen[linkKey{dev, ino}] = name
		a.Members = append(a.Members, m)
	}
	if len(a.Members) == 0 {
		return nil, fmt.Errorf("cpio: no members found")
	}
	a.Notes = append(a.Notes, "cpio: missing TRAILER!!! — archive may be truncated")
	return a, nil
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

// Build encodes mems in the given variant ("newc", "crc", or "odc").
func Build(variant string, mems []member.Member) ([]byte, error) {
	switch variant {
	case "newc", "crc":
		return buildNewc(variant, mems)
	case "odc":
		return buildOdc(mems)
	case "", "bin", "binary", "binary-swap":
		return nil, fmt.Errorf("cpio: the binary variant is read-only")
	}
	return nil, fmt.Errorf("cpio: unknown format %q", variant)
}

// assignInodes gives every member the (dev,ino) identity cpio link
// entries need: real inodes where the members carry them, a stable
// synthetic number otherwise, and hard links sharing their target's.
func assignInodes(mems []member.Member) []uint64 {
	ids := map[string]uint64{}
	next := uint64(0)
	fresh := func() uint64 {
		next++
		return 90000 + next
	}
	out := make([]uint64, len(mems))
	for i := range mems {
		m := &mems[i]
		switch {
		case m.Ino != 0:
			out[i] = m.Ino
			if _, ok := ids[m.Name]; !ok {
				ids[m.Name] = m.Ino
			}
		case m.Kind == member.HardLink:
			if v, ok := ids[m.LinkName]; ok {
				out[i] = v
			} else {
				out[i] = fresh()
			}
		default:
			out[i] = fresh()
			ids[m.Name] = out[i]
		}
	}
	return out
}

func buildNewc(variant string, mems []member.Member) ([]byte, error) {
	magic := "070701"
	if variant == "crc" {
		magic = "070702"
	}
	inos := assignInodes(mems)
	var out []byte
	appendEntry := func(ino uint64, m *member.Member, name string, data []byte) {
		nlink := m.NLink
		if nlink < 1 {
			nlink = 1
		}
		var check uint64
		if variant == "crc" {
			check = uint64(checksum32(data))
		}
		f := func(v uint64) string { return fmt.Sprintf("%08x", v) }
		hdr := magic +
			f(ino) + f(modeWord(m)) + f(uint64(uint32(m.UID))) + f(uint64(uint32(m.GID))) +
			f(uint64(nlink)) + f(uint64(mtimeOf(m))) + f(uint64(len(data))) +
			f(0) + f(0) + // archive member's own device: unused on write
			f(uint64(m.DevMajor)) + f(uint64(m.DevMinor)) +
			f(uint64(len(name)+1)) + f(check)
		out = append(out, hdr...)
		out = append(out, name...)
		out = append(out, 0)
		out = append(out, make([]byte, pad4(110+len(name)+1))...)
		out = append(out, data...)
		out = append(out, make([]byte, pad4(len(data)))...)
	}
	for i := range mems {
		m := &mems[i]
		data := m.Data
		if m.Kind == member.HardLink {
			data = nil
		}
		appendEntry(inos[i], m, m.Name, data)
	}
	appendEntry(0, &member.Member{}, Trailer, nil)
	return out, nil
}

func buildOdc(mems []member.Member) ([]byte, error) {
	inos := assignInodes(mems)
	// The 6-octal-digit fields cannot hold a modern inode number (APFS
	// inodes need 7+ digits, and %06o pads but never truncates), so
	// remap distinct identities to 1..N — link families keep sharing.
	remap := map[uint64]uint64{}
	for i, v := range inos {
		if _, ok := remap[v]; !ok {
			remap[v] = uint64(len(remap) + 1)
		}
		inos[i] = remap[v]
	}
	var out []byte
	appendEntry := func(ino uint64, m *member.Member, name string, data []byte) error {
		nlink := m.NLink
		if nlink < 1 {
			nlink = 1
		}
		if uint64(mtimeOf(m)) > 0o77777777777 || uint64(len(data)) > 0o77777777777 {
			return fmt.Errorf("cpio: odc cannot hold %s (field overflow)", m.Name)
		}
		rdev := uint64(m.DevMajor)<<8 | uint64(m.DevMinor)
		oct := func(v uint64, n int) string { return fmt.Sprintf("%0*o", n, v) }
		out = append(out, "070707"...)
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
			out = append(out, oct(fld.v, fld.n)...)
		}
		out = append(out, name...)
		out = append(out, 0)
		out = append(out, data...)
		return nil
	}
	for i := range mems {
		m := &mems[i]
		data := m.Data
		if m.Kind == member.HardLink {
			data = nil
		}
		if err := appendEntry(inos[i], m, m.Name, data); err != nil {
			return nil, err
		}
	}
	if err := appendEntry(0, &member.Member{}, Trailer, nil); err != nil {
		return nil, err
	}
	return out, nil
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
