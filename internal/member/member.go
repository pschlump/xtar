/*
Copyright (C) Philip Schlump, 2012-2026.

BSD 3 Clause Licensed.
*/

// Package member defines the in-memory representation of one archive
// entry that every container format xtar reads and writes shares.
// The whole-buffer model of the pluto codecs extends to members:
// Regular and SymLink content is held in Data in full.
package member

import (
	"fmt"
	"os"
	"time"
)

// Kind classifies a member the way the stat(2) S_IFMT type bits do.
type Kind uint8

const (
	Regular   Kind = iota // regular file
	HardLink              // second name for an earlier Regular member
	SymLink               // symbolic link; Data holds the target path
	CharDev               // character device
	BlockDev              // block device
	Directory             // directory
	FIFO                  // named pipe
)

func (k Kind) String() string {
	switch k {
	case Regular:
		return "file"
	case HardLink:
		return "hardlink"
	case SymLink:
		return "symlink"
	case CharDev:
		return "chardev"
	case BlockDev:
		return "blockdev"
	case Directory:
		return "directory"
	case FIFO:
		return "fifo"
	}
	return "unknown"
}

// TypeBits returns the stat(2) type bits (S_IFREG and friends) so the
// cpio and zip writers can fold the kind into a UNIX mode word.
func (k Kind) TypeBits() uint32 {
	switch k {
	case Regular, HardLink:
		return 0o100000
	case SymLink:
		return 0o120000
	case CharDev:
		return 0o020000
	case BlockDev:
		return 0o060000
	case Directory:
		return 0o040000
	case FIFO:
		return 0o010000
	}
	return 0
}

// Member is one archive entry.  Names are cleaned relative paths,
// '/'-separated, with no leading "./" or "/" and no trailing '/'
// (directories included).
type Member struct {
	Name     string
	LinkName string // symlink target, or hard-link target member name
	Kind     Kind
	Mode     uint32 // permission bits only: 0777 plus setuid/setgid/sticky
	UID, GID int
	Uname    string
	Gname    string
	ModTime  time.Time
	Size     int64 // len(Data) for data-carrying kinds; 0 otherwise
	DevMajor uint32
	DevMinor uint32
	NLink    uint32
	Ino      uint64 // cpio link identity; 0 when the container has none
	Dev      uint64

	Data []byte // Regular content, or the symlink target

	Comment    string // zip member comment
	Method     uint16 // zip write preference: 0 store, 8 deflate, 12 bzip2
	Encrypted  bool   // zip write request (traditional PKWARE)
	KeepStored bool   // zip rebuild: rewrite Raw untouched

	// ZipRaw preserves a zip entry exactly as stored so that update
	// and delete rebuilds are lossless (and do not need a password
	// for untouched encrypted entries).  Nil for non-zip origins.
	Raw *ZipRaw
}

// ZipRaw is the verbatim stored form of one zip entry.
type ZipRaw struct {
	Method       uint16
	Flags        uint16
	ModTime      uint16 // DOS time
	ModDate      uint16 // DOS date
	CRC          uint32
	CompSize     uint64
	UncompSize   uint64
	Extra        []byte // local-header extra data, verbatim
	Data         []byte // raw payload (still encrypted if it was)
	Encrypted    bool
	VersionMade  uint16
	InternalAttr uint16
	ExternalAttr uint32
	Comment      string
}

func (m *Member) IsDir() bool { return m.Kind == Directory }

// DataSize is the member's content size.
func (m *Member) DataSize() int64 { return int64(len(m.Data)) }

// ModeString renders the permission bits in ls style, e.g.
// "-rwsr-xr-x".  The type character comes from the Kind.
func (m *Member) ModeString() string {
	t := '-'
	switch m.Kind {
	case Directory:
		t = 'd'
	case SymLink:
		t = 'l'
	case HardLink:
		t = 'h'
	case CharDev:
		t = 'c'
	case BlockDev:
		t = 'b'
	case FIFO:
		t = 'p'
	}
	return fmt.Sprintf("%c%s", t, permString(m.Mode))
}

func permString(mode uint32) string {
	perm := [9]rune{}
	for i := 0; i < 9; i++ {
		if mode&(1<<uint(8-i)) != 0 {
			if i%3 == 0 {
				perm[i] = 'r'
			} else if i%3 == 1 {
				perm[i] = 'w'
			} else {
				perm[i] = 'x'
			}
		} else {
			perm[i] = '-'
		}
	}
	if mode&0o4000 != 0 {
		if perm[2] == 'x' {
			perm[2] = 's'
		} else {
			perm[2] = 'S'
		}
	}
	if mode&0o2000 != 0 {
		if perm[5] == 'x' {
			perm[5] = 's'
		} else {
			perm[5] = 'S'
		}
	}
	if mode&0o1000 != 0 {
		if perm[8] == 'x' {
			perm[8] = 't'
		} else {
			perm[8] = 'T'
		}
	}
	return string(perm[:])
}

// ToFileMode converts UNIX permission+special bits to an os.FileMode
// usable with os.Chmod.
func ToFileMode(mode uint32) os.FileMode {
	fm := os.FileMode(mode & 0o777)
	if mode&0o4000 != 0 {
		fm |= os.ModeSetuid
	}
	if mode&0o2000 != 0 {
		fm |= os.ModeSetgid
	}
	if mode&0o1000 != 0 {
		fm |= os.ModeSticky
	}
	return fm
}

// FromFileMode converts an os.FileMode from stat into UNIX
// permission+special bits (type bits are dropped; carry the Kind
// separately).
func FromFileMode(m os.FileMode) uint32 {
	mode := uint32(m.Perm())
	if m&os.ModeSetuid != 0 {
		mode |= 0o4000
	}
	if m&os.ModeSetgid != 0 {
		mode |= 0o2000
	}
	if m&os.ModeSticky != 0 {
		mode |= 0o1000
	}
	return mode
}
