/*
Copyright (C) Philip Schlump, 2012-2026.

BSD 3 Clause Licensed.
*/

// Package sniff identifies an archive layer from its leading bytes.
// Extensions are hints; these magic bytes are the truth.  Detection is
// the read side of the README's sniffing table.
package sniff

// Kind classifies what a magic match means for the peel algorithm.
type Kind int

const (
	Unknown     Kind = iota // no known magic
	Compression             // a whole-stream codec: peel and sniff again
	Container               // an archive format: stop peeling
	Unsupported             // recognized but not implemented: stop with an error
)

// Result is one sniff outcome.
type Result struct {
	Format  string // "gzip","compress","bzip2","lz4","xz","zstd","tar","cpio","zip","7z","rar","ar"
	Kind    Kind
	Variant string // tar: "gnu","ustar","v7","empty"; cpio: "newc","crc","odc","binary","binary-swap"; zip: "","empty","spanned"
}

func has(b []byte, off int, m string) bool {
	if off+len(m) > len(b) {
		return false
	}
	for i := 0; i < len(m); i++ {
		if b[off+i] != m[i] {
			return false
		}
	}
	return true
}

// Detect identifies the outermost layer of b.
func Detect(b []byte) Result {
	// Stream compression codecs (peeled first).
	switch {
	case has(b, 0, "\x1f\x8b"):
		return Result{"gzip", Compression, ""}
	case has(b, 0, "\x1f\x9d"), has(b, 0, "\x1f\xa0"):
		return Result{"compress", Compression, ""}
	case has(b, 0, "BZh") && len(b) > 3 && b[3] >= '1' && b[3] <= '9':
		return Result{"bzip2", Compression, ""}
	case has(b, 0, "\x04\x22\x4d\x18"):
		return Result{"lz4", Compression, ""}
	case has(b, 0, "\xfd7zXZ\x00"):
		return Result{"xz", Compression, ""}
	case has(b, 0, "\x28\xb5\x2f\xfd"):
		return Result{"zstd", Compression, ""}
	}

	// Containers.
	switch {
	case has(b, 0, "PK\x03\x04"):
		return Result{"zip", Container, ""}
	case has(b, 0, "PK\x05\x06"):
		return Result{"zip", Container, "empty"}
	case has(b, 0, "PK\x07\x08"):
		return Result{"zip", Container, "spanned"}
	case has(b, 0, "7z\xbc\xaf\x27\x1c"):
		return Result{"7z", Container, ""}
	case has(b, 0, "Rar!\x1a\x07"):
		return Result{"rar", Unsupported, ""}
	case has(b, 0, "!<arch>\n"):
		return Result{"ar", Unsupported, ""}
	case has(b, 0, "070701"):
		return Result{"cpio", Container, "newc"}
	case has(b, 0, "070702"):
		return Result{"cpio", Container, "crc"}
	case has(b, 0, "070707"):
		return Result{"cpio", Container, "odc"}
	case len(b) >= 2 && b[0] == 0xc7 && b[1] == 0x71:
		return Result{"cpio", Container, "binary"}
	case len(b) >= 2 && b[0] == 0x71 && b[1] == 0xc7:
		return Result{"cpio", Container, "binary-swap"}
	}

	// tar has no magic at offset 0; check offset 257, then the
	// all-zero empty archive, then the v7 header checksum.
	if has(b, 257, "ustar\x00") {
		return Result{"tar", Container, "ustar"}
	}
	if has(b, 257, "ustar ") {
		return Result{"tar", Container, "gnu"}
	}
	if len(b) >= 512 && allZero(b[:512]) {
		return Result{"tar", Container, "empty"}
	}
	if len(b) >= 512 && HeaderChecksumOK(b[:512]) {
		return Result{"tar", Container, "v7"}
	}
	return Result{"", Unknown, ""}
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// HeaderChecksumOK validates a tar header checksum: the stored octal
// checksum equals the byte sum of the header with the checksum field
// read as eight spaces (unsigned, or the signed variant some
// historical tars produced).  It accepts ustar, GNU and pre-POSIX v7
// headers alike.
func HeaderChecksumOK(blk []byte) bool {
	var stored int64
	seen := false
	neg := false
	for _, c := range blk[148:156] {
		switch {
		case c == ' ' || c == 0:
			continue
		case c == '-':
			neg = true
		case c >= '0' && c <= '7':
			stored = stored*8 + int64(c-'0')
			seen = true
		default:
			return false
		}
	}
	if !seen {
		return false
	}
	if neg {
		stored = -stored
	}
	var unsigned, signed int64
	for i := 0; i < 512; i++ {
		c := int64(blk[i])
		s := int64(int8(blk[i]))
		if i >= 148 && i < 156 {
			c = ' '
			s = ' '
		}
		unsigned += c
		signed += s
	}
	return stored == unsigned || stored == signed
}
