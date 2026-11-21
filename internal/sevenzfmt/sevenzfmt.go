/*
Copyright (C) Philip Schlump, 2012-2026.

MIT Licensed.
*/

// Package sevenzfmt reads the 7z container: the signature header,
// the (possibly encoded) property-graph header, folder decode with
// bind-paired coder chains, and the FilesInfo that turns folder
// sub-streams into members.  Coders: Copy, Delta, LZMA, LZMA2, BCJ
// (x86), deflate, bzip2, and AES256-SHA256.  Compression itself comes
// from pluto.
package sevenzfmt

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"time"
	"unicode/utf16"

	"github.com/pschlump/pluto/crc"
	"github.com/pschlump/xtar/internal/member"
)

var crcTable = crc.MakeTable32(0xEDB88320)

// errPassword signals that decryption needs a password the caller did
// not supply; the CLI layer catches it to prompt.
var errPassword = errors.New("the archive is encrypted; a password is required")

// Archive is a parsed 7z archive.
type Archive struct {
	Members []member.Member
	Notes   []string
}

// coder IDs (DOC/Methods.txt).
var (
	idCopy   = []byte{0x00}
	idDelta  = []byte{0x03}
	idLZMA2  = []byte{0x21}
	idLZMA   = []byte{0x03, 0x01, 0x01}
	idPPMd   = []byte{0x03, 0x04, 0x01}
	idBCJx86 = []byte{0x03, 0x03, 0x01, 0x03}
	idDefl   = []byte{0x04, 0x01, 0x08}
	idBZip2  = []byte{0x04, 0x02, 0x02}
	idAES    = []byte{0x06, 0xF1, 0x07, 0x01}
)

// Parse decodes a 7z archive, decrypting with password when it is
// encrypted ("" means none was supplied).
func Parse(b []byte, password string) (*Archive, error) {
	if len(b) < 32 || string(b[:6]) != "7z\xBC\xAF\x27\x1C" {
		return nil, errors.New("7z: not a 7z archive")
	}
	if b[6] != 0 {
		return nil, fmt.Errorf("7z: unsupported version %d.%d", b[6], b[7])
	}
	sh := b[12:32]
	if crc.Checksum32(sh, crcTable) != binary.LittleEndian.Uint32(b[8:12]) {
		return nil, errors.New("7z: bad start-header CRC")
	}
	nho := int64(binary.LittleEndian.Uint64(sh[0:8]))
	nhs := int64(binary.LittleEndian.Uint64(sh[8:16]))
	hcrc := binary.LittleEndian.Uint32(sh[16:20])
	if nho < 0 || nhs < 0 || 32+nho+nhs > int64(len(b)) {
		return nil, errors.New("7z: header out of bounds")
	}
	hdr := b[32+nho : 32+nho+nhs]
	if crc.Checksum32(hdr, crcTable) != hcrc {
		return nil, errors.New("7z: bad header CRC")
	}

	p := &parser{b: hdr}
	if p.eof() {
		return nil, errors.New("7z: empty header")
	}
	if p.peek() == 0x17 { // kEncodedHeader: the header is itself a folder
		p.next()
		si, err := p.streamsInfo()
		if err != nil {
			return nil, err
		}
		outs, err := decodeStreams(b, si, password)
		if err != nil {
			return nil, err
		}
		if len(outs) != 1 {
			return nil, errors.New("7z: encoded header must be one folder")
		}
		p = &parser{b: outs[0]}
	}
	a := &Archive{}
	if p.peek() != 0x01 { // kHeader
		return nil, errors.New("7z: bad header id")
	}
	p.next()

	var additional *streamsInfo
	var main *streamsInfo
	var files *filesInfo
	for !p.eof() {
		id := p.next()
		if id == 0x00 { // kEnd
			break
		}
		switch id {
		case 0x02: // kArchiveProperties: skip
			if err := p.skipProperties(); err != nil {
				return nil, err
			}
		case 0x03: // kAdditionalStreamsInfo
			si, err := p.streamsInfo()
			if err != nil {
				return nil, err
			}
			additional = si
		case 0x04: // kMainStreamsInfo
			si, err := p.streamsInfo()
			if err != nil {
				return nil, err
			}
			main = si
		case 0x05: // kFilesInfo
			fi, err := p.filesInfo()
			if err != nil {
				return nil, err
			}
			files = fi
		default:
			return nil, fmt.Errorf("7z: unexpected header property 0x%02x", id)
		}
	}

	if main == nil || files == nil {
		return nil, errors.New("7z: missing streams or files")
	}
	if additional != nil {
		return nil, errors.New("7z: external stream references are not supported")
	}
	if err := assemble(b, a, main, files, password); err != nil {
		return nil, err
	}
	return a, nil
}

// ------------------------------------------------------------------
// Number and bit readers
// ------------------------------------------------------------------

type parser struct {
	b   []byte
	pos int
}

func (p *parser) eof() bool { return p.pos >= len(p.b) }
func (p *parser) peek() byte {
	return p.b[p.pos]
}
func (p *parser) at(v byte) bool { return !p.eof() && p.b[p.pos] == v }
func (p *parser) next() byte {
	v := p.b[p.pos]
	p.pos++
	return v
}

// u64 reads 7z's variable-length integer: the count of leading 1
// bits in the first byte gives the extra-byte count, the remaining
// low bits are the value's top digits.
func (p *parser) u64() (uint64, error) {
	if p.eof() {
		return 0, errors.New("7z: truncated header")
	}
	b0 := p.next()
	if b0 < 0x80 {
		return uint64(b0), nil
	}
	n := bits.LeadingZeros8(^b0)
	if n > 8 || p.pos+n > len(p.b) {
		return 0, errors.New("7z: bad number")
	}
	var v uint64
	for i := 0; i < n; i++ {
		v |= uint64(p.next()) << (8 * uint(i))
	}
	if n < 8 { // 0xFF has no data bits of its own
		v |= uint64(b0&(0xFF>>uint(n)>>1)) << (8 * uint(n))
	}
	return v, nil
}

// bitVec reads n bits, MSB first within each byte.
func (p *parser) bitVec(n int) []bool {
	out := make([]bool, n)
	var mask byte
	for i := 0; i < n; i++ {
		if mask == 0 {
			if p.eof() {
				return out
			}
			mask = 0x80
		}
		out[i] = p.b[p.pos]&mask != 0
		mask >>= 1
		if mask == 0 {
			p.pos++
		}
	}
	if mask != 0 {
		p.pos++ // a partially consumed byte still counts
	}
	return out
}

// ------------------------------------------------------------------
// Streams and folders
// ------------------------------------------------------------------

type coder struct {
	id        []byte
	numIn     int
	numOut    int
	props     []byte
	inOffset  int // index of its first input among the folder's streams
	outOffset int
}

type folder struct {
	coders    []coder
	bindIn    []int // global in-stream index per bind pair
	bindOut   []int // global out-stream index per bind pair
	packedIdx []int // in-stream indices fed by packed data; nil = single implicit
	sizes     []int64
	crc       *uint32
}

type streamsInfo struct {
	packPos   int64
	packSizes []int64
	folders   []folder
	// substreams
	numUnpack []int   // per folder; nil = all 1
	subSizes  []int64 // for folders with numUnpack != 1
	subCRCs   []uint32
	subCRCSet []bool
}

func (p *parser) streamsInfo() (*streamsInfo, error) {
	si := &streamsInfo{}
	for !p.eof() {
		switch p.peek() {
		case 0x06: // kPackInfo
			p.next()
			pos, err := p.u64()
			if err != nil {
				return nil, err
			}
			si.packPos = int64(pos)
			n, err := p.u64()
			if err != nil {
				return nil, err
			}
			if n > 1<<24 {
				return nil, errors.New("7z: too many pack streams")
			}
			for !p.eof() {
				id := p.next()
				if id == 0x00 {
					break
				}
				if id != 0x09 { // kSize
					return nil, fmt.Errorf("7z: unexpected pack property 0x%02x", id)
				}
				for i := uint64(0); i < n; i++ {
					sz, err := p.u64()
					if err != nil {
						return nil, err
					}
					si.packSizes = append(si.packSizes, int64(sz))
				}
				if p.at(0x0A) { // kCRC
					p.next()
					if _, err := p.digests(int(n)); err != nil {
						return nil, err
					}
				}
			}
		case 0x07: // kUnpackInfo
			p.next()
			if err := p.unpackInfo(si); err != nil {
				return nil, err
			}
		case 0x08: // kSubStreamsInfo
			p.next()
			if err := p.subStreams(si); err != nil {
				return nil, err
			}
		case 0x00:
			p.next()
			return si, nil
		default:
			return nil, fmt.Errorf("7z: unexpected stream property 0x%02x", p.peek())
		}
	}
	return nil, errors.New("7z: truncated streams info")
}

func (p *parser) unpackInfo(si *streamsInfo) error {
	if !p.at(0x0B) { // kFolder
		return errors.New("7z: bad unpack info")
	}
	p.next()
	nf, err := p.u64()
	if err != nil {
		return err
	}
	if nf > 1<<20 {
		return errors.New("7z: too many folders")
	}
	if p.next() != 0 { // external
		return errors.New("7z: external folders are not supported")
	}
	for i := uint64(0); i < nf; i++ {
		f, err := p.folder()
		if err != nil {
			return err
		}
		si.folders = append(si.folders, *f)
	}
	if !p.at(0x0C) { // kCodersUnpackSize
		return errors.New("7z: missing coder sizes")
	}
	p.next()
	for i := range si.folders {
		f := &si.folders[i]
		total := 0
		for _, c := range f.coders {
			total += c.numOut
		}
		for j := 0; j < total; j++ {
			sz, err := p.u64()
			if err != nil {
				return err
			}
			f.sizes = append(f.sizes, int64(sz))
		}
	}
	if p.at(0x0A) { // kCRC
		p.next()
		d, err := p.digests(len(si.folders))
		if err != nil {
			return err
		}
		for i := range si.folders {
			if d.defined[i] {
				v := d.crcs[i]
				si.folders[i].crc = &v
			}
		}
	}
	if !p.at(0x00) {
		return errors.New("7z: bad unpack info end")
	}
	p.next()
	return nil
}

func (p *parser) folder() (*folder, error) {
	nc, err := p.u64()
	if err != nil {
		return nil, err
	}
	if nc == 0 || nc > 64 {
		return nil, errors.New("7z: bad coder count")
	}
	f := &folder{}
	inTotal, outTotal := 0, 0
	for i := uint64(0); i < nc; i++ {
		if p.eof() {
			return nil, errors.New("7z: truncated folder")
		}
		flags := p.next()
		idSize := int(flags & 0x0F)
		complex := flags&0x10 != 0
		hasProps := flags&0x20 != 0
		if flags&0x80 != 0 {
			return nil, errors.New("7z: alternative methods are not supported")
		}
		if idSize == 0 || p.pos+idSize > len(p.b) {
			return nil, errors.New("7z: bad coder id")
		}
		c := coder{id: p.b[p.pos : p.pos+idSize], numIn: 1, numOut: 1, inOffset: inTotal, outOffset: outTotal}
		p.pos += idSize
		if complex {
			ni, err := p.u64()
			if err != nil {
				return nil, err
			}
			no, err := p.u64()
			if err != nil {
				return nil, err
			}
			if ni == 0 || no == 0 || ni > 4 || no > 1 {
				return nil, errors.New("7z: unsupported coder shape")
			}
			c.numIn, c.numOut = int(ni), int(no)
		}
		if hasProps {
			ps, err := p.u64()
			if err != nil {
				return nil, err
			}
			if p.pos+int(ps) > len(p.b) {
				return nil, errors.New("7z: bad coder properties")
			}
			c.props = p.b[p.pos : p.pos+int(ps)]
			p.pos += int(ps)
		}
		inTotal += c.numIn
		outTotal += c.numOut
		f.coders = append(f.coders, c)
	}
	nb := outTotal - 1
	for i := 0; i < nb; i++ {
		in, err := p.u64()
		if err != nil {
			return nil, err
		}
		out, err := p.u64()
		if err != nil {
			return nil, err
		}
		if in >= uint64(inTotal) || out >= uint64(outTotal) {
			return nil, errors.New("7z: bad bind pair")
		}
		f.bindIn = append(f.bindIn, int(in))
		f.bindOut = append(f.bindOut, int(out))
	}
	nPacked := inTotal - nb
	if nPacked > 1 {
		for i := 0; i < nPacked; i++ {
			idx, err := p.u64()
			if err != nil {
				return nil, err
			}
			if idx >= uint64(inTotal) {
				return nil, errors.New("7z: bad packed index")
			}
			f.packedIdx = append(f.packedIdx, int(idx))
		}
	}
	return f, nil
}

func (p *parser) subStreams(si *streamsInfo) error {
	nf := len(si.folders)
	if p.at(0x0D) { // kNumUnpackStream
		p.next()
		for i := 0; i < nf; i++ {
			n, err := p.u64()
			if err != nil {
				return err
			}
			si.numUnpack = append(si.numUnpack, int(n))
		}
	}
	for i := range si.numUnpack {
		if si.numUnpack[i] == 0 {
			return errors.New("7z: folder with zero substreams")
		}
	}
	if p.at(0x09) { // kSize
		p.next()
		for i := 0; i < nf; i++ {
			n := 1
			if i < len(si.numUnpack) {
				n = si.numUnpack[i]
			}
			if n == 1 {
				continue // the folder's own size covers it
			}
			for j := 1; j < n; j++ { // the last sub-stream is implied
				sz, err := p.u64()
				if err != nil {
					return err
				}
				si.subSizes = append(si.subSizes, int64(sz))
			}
		}
	}
	if p.at(0x0A) { // kCRC
		p.next()
		// Digests cover exactly the substreams without a known CRC:
		// those in folders with more than one substream, or without a
		// folder CRC.
		unknown := 0
		for i := 0; i < nf; i++ {
			n := 1
			if i < len(si.numUnpack) {
				n = si.numUnpack[i]
			}
			if n == 1 && si.folders[i].crc != nil {
				continue
			}
			unknown += n
		}
		d, err := p.digests(unknown)
		if err != nil {
			return err
		}
		si.subCRCs, si.subCRCSet = d.crcs, d.defined
	}
	if !p.at(0x00) {
		return errors.New("7z: bad substreams end")
	}
	p.next()
	return nil
}

type digests struct {
	defined []bool
	crcs    []uint32
}

func (p *parser) digests(n int) (*digests, error) {
	if p.eof() {
		return nil, errors.New("7z: truncated digests")
	}
	all := p.next() != 0
	d := &digests{defined: make([]bool, n), crcs: make([]uint32, n)}
	if all {
		for i := range d.defined {
			d.defined[i] = true
		}
	} else {
		copy(d.defined, p.bitVec(n))
	}
	for i := 0; i < n; i++ {
		if !d.defined[i] {
			continue
		}
		if p.pos+4 > len(p.b) {
			return nil, errors.New("7z: truncated digest")
		}
		d.crcs[i] = binary.LittleEndian.Uint32(p.b[p.pos:])
		p.pos += 4
	}
	return d, nil
}

func (p *parser) skipProperties() error {
	for {
		if p.eof() {
			return errors.New("7z: truncated archive properties")
		}
		typ := p.next()
		if typ == 0 {
			return nil
		}
		sz, err := p.u64()
		if err != nil {
			return err
		}
		if p.pos+int(sz) > len(p.b) {
			return errors.New("7z: bad archive property")
		}
		p.pos += int(sz)
	}
}

// ------------------------------------------------------------------
// Files
// ------------------------------------------------------------------

type filesInfo struct {
	num       int
	empty     []bool
	emptyFile []bool
	anti      []bool
	names     []string
	mtimes    []time.Time
	attrs     []uint32
	attrSet   []bool
}

func (p *parser) filesInfo() (*filesInfo, error) {
	n64, err := p.u64()
	if err != nil {
		return nil, err
	}
	if n64 > 1<<24 {
		return nil, errors.New("7z: too many files")
	}
	n := int(n64)
	fi := &filesInfo{num: n}
	for {
		if p.eof() {
			return nil, errors.New("7z: truncated files info")
		}
		typ := p.next()
		if typ == 0 {
			return fi, nil
		}
		sz, err := p.u64()
		if err != nil {
			return nil, err
		}
		if p.pos+int(sz) > len(p.b) {
			return nil, errors.New("7z: bad files property")
		}
		end := p.pos + int(sz)
		switch typ {
		case 0x0E: // kEmptyStream
			fi.empty = p.bitVec(int(n))
		case 0x0F: // kEmptyFile
			fi.emptyFile = p.bitVec(countTrue(fi.empty))
		case 0x10: // kAnti
			fi.anti = p.bitVec(countTrue(fi.empty))
		case 0x11: // kName
			if p.next() != 0 {
				return nil, errors.New("7z: external names are not supported")
			}
			fi.names = p.names(end)
		case 0x12, 0x13, 0x14: // times; only mtime is kept
			def := make([]bool, n)
			if p.next() == 0 { // AllAreDefined
				def = p.bitVec(n)
			} else {
				for i := range def {
					def[i] = true
				}
			}
			if p.next() != 0 { // external
				return nil, errors.New("7z: external times are not supported")
			}
			times := make([]time.Time, n)
			for i := 0; i < n; i++ {
				if !def[i] {
					continue
				}
				if p.pos+8 > len(p.b) {
					return nil, errors.New("7z: truncated time")
				}
				if typ == 0x14 {
					times[i] = filetime(binary.LittleEndian.Uint64(p.b[p.pos:]))
				}
				p.pos += 8
			}
			if typ == 0x14 {
				fi.mtimes = times
			}
		case 0x15: // kWinAttributes
			def := make([]bool, n)
			if p.next() == 0 { // AllAreDefined
				def = p.bitVec(n)
			} else {
				for i := range def {
					def[i] = true
				}
			}
			if p.next() != 0 { // external
				return nil, errors.New("7z: external attributes are not supported")
			}
			fi.attrs, fi.attrSet = make([]uint32, n), make([]bool, n)
			for i := 0; i < n; i++ {
				if !def[i] {
					continue
				}
				if p.pos+4 > len(p.b) {
					return nil, errors.New("7z: truncated attributes")
				}
				fi.attrs[i] = binary.LittleEndian.Uint32(p.b[p.pos:])
				fi.attrSet[i] = true
				p.pos += 4
			}
		default:
			// kStartPos, kDummy, anything newer: skip
		}
		p.pos = end // every property ends exactly at its stated size
	}
}

func (p *parser) names(end int) []string {
	var out []string
	var cur []uint16
	for p.pos < end-1 {
		c := binary.LittleEndian.Uint16(p.b[p.pos:])
		p.pos += 2
		if c == 0 {
			out = append(out, string(utf16.Decode(cur)))
			cur = nil
			continue
		}
		cur = append(cur, c)
	}
	p.pos = end
	return out
}

func countTrue(v []bool) int {
	n := 0
	for _, b := range v {
		if b {
			n++
		}
	}
	return n
}

// filetime converts a Windows FILETIME (100ns ticks since 1601) to
// time.Time.
func filetime(ft uint64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	sec := int64((ft - 116444736000000000) / 10000000)
	nsec := int32(ft%10000000) * 100
	return time.Unix(sec, int64(nsec)).UTC()
}
