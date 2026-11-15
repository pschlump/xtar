/*
Copyright (C) Philip Schlump, 2012-2026.

BSD 3 Clause Licensed.
*/

package sevenzfmt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"time"

	"github.com/pschlump/pluto/crc"
	"github.com/pschlump/pluto/lzma"
	"github.com/pschlump/xtar/internal/member"
)

// Build encodes mems as a 7z archive.  Non-empty members form one
// solid folder — LZMA at level > 0, stored bytes at level 0 — and a
// password wraps it in AES256 (2^19-round KDF, random IV).  Empty
// members and directories ride the FilesInfo bits.  Symlinks store
// their target as the member data, the way 7-Zip's -snl does.
func Build(mems []member.Member, password string, level int) ([]byte, error) {
	if password != "" && level == 0 {
		return nil, errors.New("7z: stored archives cannot be encrypted (use a compression level)")
	}

	// The solid folder: concatenate every non-empty member.
	var solid []byte
	var subCRCs []uint32
	var subSizes []int64
	for i := range mems {
		m := &mems[i]
		data := m.Data
		if m.Kind == member.SymLink {
			data = []byte(m.LinkName)
		}
		if m.Kind == member.Directory || (len(data) == 0 && m.Kind != member.SymLink) {
			continue // empty members ride the FilesInfo bits instead
		}
		solid = append(solid, data...)
		subCRCs = append(subCRCs, crc.Checksum32(data, crcTable))
		subSizes = append(subSizes, int64(len(data)))
	}
	unpacked := int64(len(solid))

	// Pack the folder: LZMA — the alone-format stream minus its
	// header; the size is known so the trailing end marker is simply
	// never reached — optionally wrapped in AES.
	const dictSize = 1 << 23
	var packed []byte
	var folder []byte
	var aesOut int64 // the AES coder's declared output: unpadded plaintext
	switch {
	case level == 0:
		packed = solid
		folder = appendCoder(putU64(nil, 1), idCopy, nil)
	case password == "":
		z := lzma.Compress(solid)
		packed = z[13:]
		props := []byte{z[0], 0, 0, 0, 0}
		binary.LittleEndian.PutUint32(props[1:], dictSize)
		folder = appendCoder(putU64(nil, 1), idLZMA, props)
	default:
		z := lzma.Compress(solid)
		props := []byte{z[0], 0, 0, 0, 0}
		binary.LittleEndian.PutUint32(props[1:], dictSize)
		iv := make([]byte, 16)
		if _, err := rand.Read(iv); err != nil {
			return nil, err
		}
		aesProps := append([]byte{19 | 1<<6, 0x0F}, iv...) // power 19, no salt, 16-byte IV
		folder = putU64(nil, 2)                            // AES feeding LZMA
		folder = appendCoder(folder, idAES, aesProps)
		folder = appendCoder(folder, idLZMA, props)
		folder = putU64(folder, 1) // bind pair: in-stream 1 (LZMA's input)
		folder = putU64(folder, 0) // takes out-stream 0 (AES's output)
		plain := z[13:]
		plainLen := int64(len(plain)) // what the coder underneath consumes
		padded := append([]byte{}, plain...)
		if r := len(padded) % 16; r != 0 {
			padded = append(padded, make([]byte, 16-r)...)
		}
		enc, err := aesEncrypt(padded, aesProps, password)
		if err != nil {
			return nil, err
		}
		packed = enc
		aesOut = plainLen
	}

	// The header.
	hdr := []byte{0x01}     // kHeader
	hdr = append(hdr, 0x04) // kMainStreamsInfo
	hdr = append(hdr, 0x06) // kPackInfo
	hdr = putU64(hdr, 0)    // packPos
	hdr = putU64(hdr, 1)    // one pack stream
	hdr = append(hdr, 0x09) // kSize
	hdr = putU64(hdr, int64(len(packed)))
	hdr = append(hdr, 0x00) // kEnd (pack)
	hdr = append(hdr, 0x07) // kUnpackInfo
	hdr = append(hdr, 0x0B) // kFolder
	hdr = putU64(hdr, 1)    // one folder
	hdr = append(hdr, 0x00) // external
	hdr = append(hdr, folder...)
	hdr = append(hdr, 0x0C) // kCodersUnpackSize
	if aesOut > 0 || (password != "" && level != 0) {
		hdr = putU64(hdr, aesOut)
		hdr = putU64(hdr, unpacked)
	} else {
		hdr = putU64(hdr, unpacked)
	}
	hdr = append(hdr, 0x00) // kEnd (unpack)
	// kSubStreamsInfo carries each member's own CRC — the shape the
	// 7-Zip CLI writes (no folder CRC).  A lone sub-stream still
	// lists its digest; sizes list n-1 with the last implied.
	hdr = append(hdr, 0x08) // kSubStreamsInfo
	if n := len(subSizes); n > 1 {
		hdr = append(hdr, 0x0D) // kNumUnpackStream
		hdr = putU64(hdr, int64(n))
		hdr = append(hdr, 0x09) // kSize
		for _, sz := range subSizes[:n-1] {
			hdr = putU64(hdr, sz)
		}
	}
	hdr = append(hdr, 0x0A) // kCRC
	if len(subCRCs) == 0 {
		subCRCs = []uint32{0} // an empty folder is one empty sub-stream
	}
	hdr = appendDigest(hdr, subCRCs)
	hdr = append(hdr, 0x00) // kEnd (substreams)
	hdr = append(hdr, 0x00) // kEnd (streams)
	hdr = appendFilesInfo(hdr, mems)
	hdr = append(hdr, 0x00) // kEnd (header)

	// The file: signature header, packed stream, next header.
	out := make([]byte, 0, 32+len(packed)+len(hdr)+16)
	out = append(out, '7', 'z', 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04)
	var sh [20]byte
	binary.LittleEndian.PutUint64(sh[0:8], uint64(len(packed)))
	binary.LittleEndian.PutUint64(sh[8:16], uint64(len(hdr)))
	binary.LittleEndian.PutUint32(sh[16:20], crc.Checksum32(hdr, crcTable))
	out = binary.LittleEndian.AppendUint32(out, crc.Checksum32(sh[:], crcTable))
	out = append(out, sh[:]...)
	out = append(out, packed...)
	out = append(out, hdr...)
	return out, nil
}

// appendCoder writes one coder record: flags, id, properties.
func appendCoder(dst, id, props []byte) []byte {
	dst = append(dst, byte(len(id))|0x20)
	dst = append(dst, id...)
	dst = putU64(dst, int64(len(props)))
	return append(dst, props...)
}

// aesEncrypt is aesDecode's inverse over the same properties and key
// derivation.
func aesEncrypt(in, props []byte, password string) ([]byte, error) {
	b0 := props[0]
	power := int(b0 & 0x3F)
	var salt, iv []byte
	if b0&0xC0 != 0 {
		b1 := props[1]
		saltSize := int(b0>>7&1) + int(b1>>4)
		ivSize := int(b0>>6&1) + int(b1&0x0F)
		salt = props[2 : 2+saltSize]
		iv = props[2+saltSize : 2+saltSize+ivSize]
	}
	if password == "" {
		return nil, errPassword
	}
	key := deriveKey(salt, utf16LE(password), power)
	iv16 := make([]byte, 16)
	copy(iv16, iv)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(in)%16 != 0 {
		return nil, errors.New("7z: AES plaintext must be block aligned")
	}
	out := make([]byte, len(in))
	cipher.NewCBCEncrypter(block, iv16).CryptBlocks(out, in)
	return out, nil
}

// appendDigest writes a digests block with every CRC defined.
func appendDigest(dst []byte, crcs []uint32) []byte {
	dst = append(dst, 1) // all are defined
	for _, c := range crcs {
		dst = binary.LittleEndian.AppendUint32(dst, c)
	}
	return dst
}

// appendFilesInfo writes empty-stream/empty-file bits, names, times,
// and attributes.
func appendFilesInfo(dst []byte, mems []member.Member) []byte {
	d := append(dst, 0x05)
	d = putU64(d, int64(len(mems)))

	var emptyBits, fileBits []bool
	for i := range mems {
		m := &mems[i]
		empty := m.Kind == member.Directory || (len(m.Data) == 0 && m.Kind != member.SymLink)
		emptyBits = append(emptyBits, empty)
		if empty {
			fileBits = append(fileBits, m.Kind != member.Directory)
		}
	}
	if anyTrue(emptyBits) {
		d = append(d, 0x0E) // kEmptyStream
		d = putU64(d, int64((len(emptyBits)+7)/8))
		d = appendBits(d, emptyBits)
		if anyTrue(fileBits) {
			d = append(d, 0x0F) // kEmptyFile
			d = putU64(d, int64((len(fileBits)+7)/8))
			d = appendBits(d, fileBits)
		}
	}

	// kName
	var names []byte
	for i := range mems {
		for _, u := range utf16Encode(mems[i].Name) {
			names = binary.LittleEndian.AppendUint16(names, u)
		}
		names = append(names, 0, 0)
	}
	d = append(d, 0x11)
	d = putU64(d, int64(len(names)+1))
	d = append(d, 0x00) // external
	d = append(d, names...)

	// kMTime
	var times []byte
	for i := range mems {
		times = binary.LittleEndian.AppendUint64(times, toFiletime(mems[i].ModTime))
	}
	d = append(d, 0x14)
	d = putU64(d, int64(len(times)+2))
	d = append(d, 0x01) // all defined
	d = append(d, 0x00) // external
	d = append(d, times...)

	// kWinAttributes
	var attrs []byte
	for i := range mems {
		a := (mems[i].Mode|mems[i].Kind.TypeBits())<<16 | 0x8000
		if mems[i].Kind == member.Directory {
			a |= 0x10
		}
		attrs = binary.LittleEndian.AppendUint32(attrs, a)
	}
	d = append(d, 0x15)
	d = putU64(d, int64(len(attrs)+2))
	d = append(d, 0x01) // all defined
	d = append(d, 0x00) // external
	d = append(d, attrs...)

	return append(d, 0x00) // kEnd (files)
}

func anyTrue(v []bool) bool {
	for _, b := range v {
		if b {
			return true
		}
	}
	return false
}

func appendBits(dst []byte, v []bool) []byte {
	var b byte
	mask := byte(0x80)
	for _, set := range v {
		if set {
			b |= mask
		}
		mask >>= 1
		if mask == 0 {
			dst = append(dst, b)
			b, mask = 0, 0x80
		}
	}
	if mask != 0 {
		dst = append(dst, b)
	}
	return dst
}

// toFiletime converts a time to Windows FILETIME (100ns ticks since
// 1601); the zero time maps to 0.
func toFiletime(t time.Time) uint64 {
	if t.IsZero() {
		return 0
	}
	ft := t.UTC().UnixNano()/100 + 116444736000000000
	if ft < 0 {
		return 0
	}
	return uint64(ft)
}

func utf16Encode(s string) []uint16 {
	runes := []rune(s)
	out := make([]uint16, 0, len(runes))
	for _, r := range runes {
		if r < 0x10000 {
			out = append(out, uint16(r))
		} else {
			r -= 0x10000
			out = append(out, uint16(0xD800+r>>10), uint16(0xDC00+r&0x3FF))
		}
	}
	return out
}

// putU64 appends a 7z variable-length integer: the smallest count of
// leading 1-bits that fits the value, top digits in the first byte,
// the low 8n digits in n little-endian trailing bytes.
func putU64(dst []byte, v int64) []byte {
	u := uint64(v)
	n := 0
	for n < 8 && u >= 1<<uint(7*(n+1)) {
		n++
	}
	if n == 0 {
		return append(dst, byte(u))
	}
	if n == 8 {
		dst = append(dst, 0xFF)
		return append(dst, littleBytes(u, 8)...)
	}
	first := byte(0xFF << uint(8-n))
	first |= byte(u >> (8 * uint(n)))
	dst = append(dst, first)
	return append(dst, littleBytes(u, n)...)
}

func littleBytes(v uint64, n int) []byte {
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = byte(v >> (8 * uint(i)))
	}
	return out
}
