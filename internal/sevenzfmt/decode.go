/*
Copyright (C) Philip Schlump, 2012-2026.

MIT Licensed.
*/

package sevenzfmt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"fmt"
	"unicode/utf16"

	"github.com/pschlump/pluto/bzip2"
	"github.com/pschlump/pluto/crc"
	"github.com/pschlump/pluto/deflate"
	"github.com/pschlump/pluto/lzma"
	"github.com/pschlump/pluto/xz"
	"github.com/pschlump/xtar/internal/member"
)

// decodeStreams decodes every folder of a streamsInfo into its output
// stream.  Packed streams are slices of the file past the 32-byte
// signature header; folders consume them in order.
func decodeStreams(b []byte, si *streamsInfo, password string) ([][]byte, error) {
	packs := make([][]byte, len(si.packSizes))
	off := 32 + si.packPos
	for i, sz := range si.packSizes {
		if sz < 0 || off+sz > int64(len(b)) {
			return nil, errors.New("7z: packed stream out of bounds")
		}
		packs[i] = b[off : off+sz]
		off += sz
	}
	var outs [][]byte
	cur := 0 // packed-stream cursor
	for i := range si.folders {
		f := &si.folders[i]
		nPacked := f.packedCount()
		if cur+nPacked > len(packs) {
			return nil, errors.New("7z: not enough packed streams")
		}
		out, err := f.decode(packs[cur:cur+nPacked], password)
		if err != nil {
			return nil, err
		}
		cur += nPacked
		outs = append(outs, out)
	}
	return outs, nil
}

// packedCount is how many packed streams the folder consumes.
func (f *folder) packedCount() int {
	if len(f.packedIdx) > 0 {
		return len(f.packedIdx)
	}
	inTotal := 0
	for _, c := range f.coders {
		inTotal += c.numIn
	}
	return inTotal - len(f.bindIn)
}

// decode runs the folder's coder graph.  Packed bytes enter at the
// unbound input streams (the folder's packed indices name them in
// pack order, or the single unbound input when there is no list);
// bind pairs carry coder outputs to coder inputs; the one unbound
// output is the folder's result.
func (f *folder) decode(packs [][]byte, password string) ([]byte, error) {
	inTotal, outTotal := 0, 0
	for _, c := range f.coders {
		inTotal += c.numIn
		outTotal += c.numOut
	}
	bound := map[int]bool{}
	for _, in := range f.bindIn {
		bound[in] = true
	}
	var openIns []int
	for i := 0; i < inTotal; i++ {
		if !bound[i] {
			openIns = append(openIns, i)
		}
	}
	if len(openIns) != len(packs) {
		return nil, errors.New("7z: folder inputs do not match its packed streams")
	}
	inputs := make([][]byte, inTotal)
	if len(f.packedIdx) == len(packs) {
		for i, idx := range f.packedIdx {
			inputs[idx] = packs[i]
		}
	} else {
		for i, idx := range openIns {
			inputs[idx] = packs[i]
		}
	}
	outputs := make([][]byte, outTotal)
	done := make([]bool, len(f.coders))
	for round := 0; ; round++ {
		if round > len(f.coders) {
			return nil, errors.New("7z: folder coder graph is cyclic")
		}
		progress := false
		allDone := true
		for ci, c := range f.coders {
			if done[ci] {
				continue
			}
			allDone = false
			ready := true
			for i := 0; i < c.numIn; i++ {
				if inputs[c.inOffset+i] == nil {
					ready = false
					break
				}
			}
			if !ready {
				continue
			}
			ins := inputs[c.inOffset : c.inOffset+c.numIn]
			sz := f.sizes[c.outOffset]
			out, err := decodeCoder(c, ins, sz, password)
			if err != nil {
				return nil, err
			}
			outputs[c.outOffset] = out
			done[ci] = true
			progress = true
			// feed bound inputs from this coder's output
			for bi, outIdx := range f.bindOut {
				if outIdx == c.outOffset {
					inputs[f.bindIn[bi]] = out
				}
			}
		}
		if allDone {
			break
		}
		if !progress {
			return nil, errors.New("7z: folder coder graph is stuck")
		}
	}
	// the folder output: the unbound out-stream
	boundOut := map[int]bool{}
	for _, o := range f.bindOut {
		boundOut[o] = true
	}
	for i, out := range outputs {
		if !boundOut[i] {
			if f.crc != nil && crc.Checksum32(out, crcTable) != *f.crc {
				return nil, errors.New("7z: folder CRC mismatch")
			}
			return out, nil
		}
	}
	return nil, errors.New("7z: folder has no output stream")
}

// decodeCoder runs one coder.  v1 handles one-output coders only.
func decodeCoder(c coder, ins [][]byte, outSize int64, password string) ([]byte, error) {
	switch {
	case bytes.Equal(c.id, idCopy):
		return ins[0], nil
	case bytes.Equal(c.id, idDelta):
		if len(c.props) != 1 {
			return nil, errors.New("7z: bad delta properties")
		}
		out := append([]byte{}, ins[0]...)
		dist := int(c.props[0]) + 1
		for i := dist; i < len(out); i++ {
			out[i] += out[i-dist]
		}
		return out, nil
	case bytes.Equal(c.id, idLZMA):
		out := lzma.DecodeRaw(ins[0], c.props, outSize)
		if out == nil {
			return nil, errors.New("7z: bad LZMA stream")
		}
		return out, nil
	case bytes.Equal(c.id, idLZMA2):
		if len(c.props) != 1 {
			return nil, errors.New("7z: bad LZMA2 properties")
		}
		out := xz.DecodeLZMA2(ins[0], c.props[0], outSize)
		if out == nil {
			return nil, errors.New("7z: bad LZMA2 stream")
		}
		return out, nil
	case bytes.Equal(c.id, idBCJx86):
		return bcjX86(ins[0]), nil
	case bytes.Equal(c.id, idDefl):
		out, _ := deflate.Expand(ins[0])
		if out == nil {
			return nil, errors.New("7z: bad deflate stream")
		}
		return out, nil
	case bytes.Equal(c.id, idBZip2):
		out := bzip2.Expand(ins[0])
		if out == nil {
			return nil, errors.New("7z: bad bzip2 stream")
		}
		return out, nil
	case bytes.Equal(c.id, idAES):
		return aesDecode(ins[0], c.props, password)
	default:
		return nil, fmt.Errorf("7z: coder % x is not supported", c.id)
	}
}

// bcjX86 converts an x86 BCJ-filtered stream back to the original:
// E8/E9 rel32 displacements were rewritten to be relative to zero;
// adding the position back restores them.  The masked-lookback dance
// (from Igor Pavlov's reference) keeps conversions from firing on
// bytes that were not really displacements.
func bcjX86(b []byte) []byte {
	const (
		prevMaskStart = 0
		prevPosStart  = -5
	)
	if len(b) < 5 {
		return b
	}
	prevMask := uint32(prevMaskStart)
	prevPos := int32(prevPosStart)
	limit := len(b) - 5
	maskToBit := [5]uint32{0, 1, 2, 2, 3}
	out := append([]byte{}, b...)
	for i := 0; i <= limit; {
		c := out[i]
		if c != 0xE8 && c != 0xE9 {
			i++
			continue
		}
		offset := uint32(int32(i) - prevPos)
		prevPos = int32(i)
		if offset > 5 {
			prevMask = 0
		} else {
			for j := uint32(0); j < offset; j++ {
				prevMask &= 0x77
				prevMask <<= 1
			}
		}
		msb := out[i+4]
		if (msb == 0 || msb == 0xFF) && prevMask>>1 <= 4 && prevMask>>1 != 3 {
			src := uint32(msb)<<24 | uint32(out[i+3])<<16 | uint32(out[i+2])<<8 | uint32(out[i+1])
			var dest uint32
			for {
				dest = src - uint32(i+5) // decode direction
				if prevMask == 0 {
					break
				}
				bit := maskToBit[prevMask>>1]
				msb = byte(dest >> (24 - bit*8))
				if msb != 0 && msb != 0xFF {
					break
				}
				src = dest ^ (uint32(1)<<(32-bit*8) - 1)
			}
			if dest>>24&1 == 1 { // restore the displacement's sign byte
				out[i+4] = 0xFF
			} else {
				out[i+4] = 0x00
			}
			out[i+3] = byte(dest >> 16)
			out[i+2] = byte(dest >> 8)
			out[i+1] = byte(dest)
			i += 5
			prevMask = 0
		} else {
			i++
			prevMask |= 1
			if msb == 0 || msb == 0xFF {
				prevMask |= 0x10
			}
		}
	}
	return out
}

// aesDecode decrypts a 7z AES256-SHA256 coder stream: the properties
// carry the KDF power, salt, and IV; the key is SHA-256 over
// salt+password repeated 2^power times with a little-endian round
// counter trailing each block; the cipher is AES-256-CBC without
// padding.
func aesDecode(in, props []byte, password string) ([]byte, error) {
	if len(props) < 1 {
		return nil, errors.New("7z: bad AES properties")
	}
	b0 := props[0]
	power := int(b0 & 0x3F)
	var salt, iv []byte
	if b0&0xC0 != 0 {
		if len(props) < 2 {
			return nil, errors.New("7z: bad AES properties")
		}
		b1 := props[1]
		saltSize := int(b0>>7&1) + int(b1>>4)
		ivSize := int(b0>>6&1) + int(b1&0x0F)
		if len(props) != 2+saltSize+ivSize {
			return nil, errors.New("7z: bad AES properties")
		}
		salt = props[2 : 2+saltSize]
		iv = props[2+saltSize : 2+saltSize+ivSize]
	}
	if password == "" {
		return nil, errPassword
	}
	pw := utf16LE(password)
	key := deriveKey(salt, pw, power)
	iv16 := make([]byte, 16)
	copy(iv16, iv)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(in)%16 != 0 {
		return nil, errors.New("7z: encrypted stream is not block aligned")
	}
	out := make([]byte, len(in))
	cipher.NewCBCDecrypter(block, iv16).CryptBlocks(out, in)
	return out, nil
}

// deriveKey is 7z's KDF: rounds of SHA-256 over salt+password, each
// block suffixed with a little-endian round counter.
func deriveKey(salt, pw []byte, power int) []byte {
	const keySize = 32
	if power == 0x3F { // no hashing: salt+password padded with zeros
		key := make([]byte, keySize)
		copy(key, salt)
		copy(key[len(salt):], pw)
		return key
	}
	buf := make([]byte, 0, len(salt)+len(pw)+8)
	buf = append(buf, salt...)
	buf = append(buf, pw...)
	buf = append(buf, 0, 0, 0, 0, 0, 0, 0, 0)
	h := sha256.New()
	ctr := uint32(0)
	for i := 0; i < 1<<uint(power); i++ {
		buf[len(buf)-8] = byte(ctr)
		buf[len(buf)-7] = byte(ctr >> 8)
		buf[len(buf)-6] = byte(ctr >> 16)
		buf[len(buf)-5] = byte(ctr >> 24)
		h.Write(buf)
		ctr++
	}
	return h.Sum(nil)
}

func utf16LE(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, len(units)*2)
	for i, u := range units {
		out[i*2] = byte(u)
		out[i*2+1] = byte(u >> 8)
	}
	return out
}

// ------------------------------------------------------------------
// Members
// ------------------------------------------------------------------

// assemble decodes the main streams and splits folder sub-streams
// into members, pairing them with the FilesInfo entries.
func assemble(b []byte, a *Archive, si *streamsInfo, files *filesInfo, password string) error {
	outs, err := decodeStreams(b, si, password)
	if err != nil {
		return err
	}

	// Split each folder into its sub-streams.  The size list covers
	// only folders with more than one sub-stream, and within those
	// only the first n-1: the last takes whatever remains of the
	// folder's output.
	var streams [][]byte
	var streamCRC []uint32
	var crcKnown []bool
	crcIdx := 0
	sizeIdx := 0
	for fi := range si.folders {
		n := 1
		if fi < len(si.numUnpack) {
			n = si.numUnpack[fi]
		}
		out := outs[fi]
		sizes := []int64{int64(len(out))}
		if n > 1 {
			folderSize := si.folders[fi].sizes[len(si.folders[fi].sizes)-1]
			sizes = nil
			var total int64
			for i := 0; i < n-1; i++ {
				sz := si.subSizes[sizeIdx]
				sizeIdx++
				sizes = append(sizes, sz)
				total += sz
			}
			if folderSize-total < 0 {
				return errors.New("7z: sub-stream sizes exceed folder size")
			}
			sizes = append(sizes, folderSize-total)
		}
		pos := int64(0)
		for i := 0; i < n; i++ {
			if pos+sizes[i] > int64(len(out)) {
				return errors.New("7z: sub-stream exceeds folder size")
			}
			streams = append(streams, out[pos:pos+sizes[i]])
			pos += sizes[i]
			if n == 1 && si.folders[fi].crc != nil {
				streamCRC, crcKnown = append(streamCRC, *si.folders[fi].crc), append(crcKnown, true)
			} else if crcIdx < len(si.subCRCs) {
				streamCRC, crcKnown = append(streamCRC, si.subCRCs[crcIdx]), append(crcKnown, si.subCRCSet[crcIdx])
				crcIdx++
			} else {
				streamCRC, crcKnown = append(streamCRC, 0), append(crcKnown, false)
			}
		}
	}

	stream := 0
	emptyIdx := 0 // kEmptyFile/kAnti bits index the empty-stream files
	for i := 0; i < files.num; i++ {
		name := ""
		if i < len(files.names) {
			name = files.names[i]
		}
		var m member.Member
		m.Name = name
		if i < len(files.mtimes) {
			m.ModTime = files.mtimes[i]
		}
		if i < len(files.empty) && files.empty[i] {
			// a directory, an empty file, or an anti file
			isEmptyFile := emptyIdx < len(files.emptyFile) && files.emptyFile[emptyIdx]
			emptyIdx++
			if !isEmptyFile {
				m.Kind = member.Directory
			} else {
				m.Kind = member.Regular
			}
		} else {
			if stream >= len(streams) {
				return errors.New("7z: not enough sub-streams for files")
			}
			data := streams[stream]
			if crcKnown[stream] && crc.Checksum32(data, crcTable) != streamCRC[stream] {
				return fmt.Errorf("7z: %s: CRC mismatch", name)
			}
			stream++
			m.Kind = member.Regular
			m.Data, m.Size = data, int64(len(data))
		}
		applyAttrs(&m, files, i)
		if m.Kind == member.SymLink {
			m.LinkName = string(m.Data)
		}
		a.Members = append(a.Members, m)
	}
	return nil
}

// applyAttrs maps Windows attributes to kind and mode, honoring the
// UNIX extension (the posix mode word in the high half, flagged by
// 0x8000 in the low half).
func applyAttrs(m *member.Member, files *filesInfo, i int) {
	if i >= len(files.attrs) || !files.attrSet[i] {
		if m.Kind == member.Directory && m.Mode == 0 {
			m.Mode = 0o755
		} else if m.Mode == 0 {
			m.Mode = 0o644
		}
		return
	}
	attr := files.attrs[i]
	if attr&0x8000 != 0 && attr>>16 != 0 {
		mode := attr >> 16
		m.Mode = mode & 0o7777
		switch mode & 0o170000 {
		case 0o040000:
			m.Kind = member.Directory
		case 0o120000:
			m.Kind = member.SymLink
		case 0o100000:
			if m.Kind != member.Directory {
				m.Kind = member.Regular
			}
		}
		return
	}
	if attr&0x10 != 0 { // FILE_ATTRIBUTE_DIRECTORY
		m.Kind = member.Directory
	}
	if m.Kind == member.Directory && m.Mode == 0 {
		m.Mode = 0o755
	} else if m.Mode == 0 {
		m.Mode = 0o644
	}
}
