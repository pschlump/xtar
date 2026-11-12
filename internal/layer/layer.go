/*
Copyright (C) Philip Schlump, 2012-2026.

BSD 3 Clause Licensed.
*/

// Package layer adapts the whole-buffer pluto codecs into named
// stream-compression layers the peel engine can apply.  The pluto
// functions report failure by returning nil; the wrappers turn that
// into an error.
package layer

import (
	"fmt"

	"github.com/pschlump/pluto/bzip2"
	"github.com/pschlump/pluto/compress_z"
	"github.com/pschlump/pluto/deflate"
	"github.com/pschlump/pluto/gzip"
	"github.com/pschlump/pluto/lz4"
	"github.com/pschlump/pluto/zlib"
)

// Codec is one whole-buffer stream codec.  Compress never fails (the
// pluto encoders accept any input); Expand fails only on a corrupt or
// truncated stream.
type Codec struct {
	Name     string
	Compress func([]byte) ([]byte, error)
	Expand   func([]byte) ([]byte, error)

	// Level, when set, is the level-aware encoder (bzip2 -1..-9).
	// Other codecs have a single level; CompressLevel falls back.
	Level func(data []byte, level int) []byte
}

// CompressLevel compresses at the given level when the codec has one.
func (c Codec) CompressLevel(data []byte, level int) ([]byte, error) {
	if c.Level != nil && level >= 1 && level <= 9 {
		return c.Level(data, level), nil
	}
	return c.Compress(data)
}

func wrap(name string, compress func([]byte) []byte, expand func([]byte) []byte) Codec {
	return Codec{
		Name: name,
		Compress: func(in []byte) ([]byte, error) {
			out := compress(in)
			if out == nil {
				return nil, fmt.Errorf("%s: encoder failed", name)
			}
			return out, nil
		},
		Expand: func(in []byte) ([]byte, error) {
			out := expand(in)
			if out == nil {
				return nil, fmt.Errorf("%s: corrupt or truncated stream", name)
			}
			return out, nil
		},
	}
}

var byName = map[string]Codec{
	"gzip": wrap("gzip", gzip.Compress, gzip.Expand),
	"bzip2": func() Codec {
		c := wrap("bzip2", bzip2.Compress, bzip2.Expand)
		c.Level = bzip2.CompressLevel
		return c
	}(),
	"compress": wrap("compress", compress_z.Compress, compress_z.Expand),
	"lz4":      wrap("lz4", lz4.Compress, lz4.Expand),
	"zlib":     wrap("zlib", zlib.Compress, zlib.Expand),
	"deflate":  wrap("deflate", deflate.Compress, deflateExpand),
}

func deflateExpand(b []byte) []byte {
	out, _ := deflate.Expand(b)
	return out
}

// ByName returns the codec registered under name.
func ByName(name string) (Codec, bool) {
	c, ok := byName[name]
	return c, ok
}

// Expand decompresses b with the named codec.
func Expand(name string, b []byte) ([]byte, error) {
	c, ok := byName[name]
	if !ok {
		return nil, fmt.Errorf("unknown compression layer %q", name)
	}
	return c.Expand(b)
}

// Compress compresses b with the named codec.
func Compress(name string, b []byte) ([]byte, error) {
	c, ok := byName[name]
	if !ok {
		return nil, fmt.Errorf("unknown compression layer %q", name)
	}
	return c.Compress(b)
}

// CompressLevel compresses b with the named codec at a level.
func CompressLevel(name string, b []byte, level int) ([]byte, error) {
	c, ok := byName[name]
	if !ok {
		return nil, fmt.Errorf("unknown compression layer %q", name)
	}
	return c.CompressLevel(b, level)
}
