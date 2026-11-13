/*
Copyright (C) Philip Schlump, 2012-2026.

BSD 3 Clause Licensed.
*/

// Package layer adapts the pluto codecs into named stream-compression
// layers the peel engine can apply: whole-buffer Compress/Expand pairs
// and, since pluto grew streaming types, io.Reader/io.Writer forms.
// The pluto whole-buffer functions report failure by returning nil;
// the wrappers turn that into an error.  The streaming types report
// errors the usual io way (sticky, from Read/Write/Close).
package layer

import (
	"fmt"
	"io"

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

// ------------------------------------------------------------------
// Streaming (over the pluto NewReader/NewWriter types)
// ------------------------------------------------------------------

// StreamWriter is the streaming encoder every pluto codec writer
// satisfies: Write buffers into the codec, Flush pushes a decodable
// boundary where the format has one, Close finishes the stream (never
// closes the underlying destination).
type StreamWriter interface {
	io.Writer
	Flush() error
	Close() error
}

// streamCodec is one codec's streaming constructors.
type streamCodec struct {
	newReader func(io.Reader) io.ReadCloser
	newWriter func(io.Writer) StreamWriter
	level     func(io.Writer, int) StreamWriter // bzip2 only
}

var streamByName = map[string]streamCodec{
	"gzip": {
		newReader: func(r io.Reader) io.ReadCloser { return gzip.NewReader(r) },
		newWriter: func(w io.Writer) StreamWriter { return gzip.NewWriter(w) },
	},
	"bzip2": {
		newReader: func(r io.Reader) io.ReadCloser { return bzip2.NewReader(r) },
		newWriter: func(w io.Writer) StreamWriter { return bzip2.NewWriter(w) },
		level:     func(w io.Writer, lvl int) StreamWriter { return bzip2.NewWriterLevel(w, lvl) },
	},
	"compress": {
		newReader: func(r io.Reader) io.ReadCloser { return compress_z.NewReader(r) },
		newWriter: func(w io.Writer) StreamWriter { return compress_z.NewWriter(w) },
	},
	"lz4": {
		newReader: func(r io.Reader) io.ReadCloser { return lz4.NewReader(r) },
		newWriter: func(w io.Writer) StreamWriter { return lz4.NewWriter(w) },
	},
	"zlib": {
		newReader: func(r io.Reader) io.ReadCloser { return zlib.NewReader(r) },
		newWriter: func(w io.Writer) StreamWriter { return zlib.NewWriter(w) },
	},
	"deflate": {
		newReader: func(r io.Reader) io.ReadCloser { return deflate.NewReader(r) },
		newWriter: func(w io.Writer) StreamWriter { return deflate.NewWriter(w) },
	},
}

// NewReader wraps r in the named codec's streaming decoder.  Errors —
// corruption (wrapping the codec's ErrMalformed) or truncation
// (io.ErrUnexpectedEOF) — surface from Read, sticky, exactly as the
// whole-buffer Expand's nil does, and Close reports them.
func NewReader(name string, r io.Reader) (io.ReadCloser, error) {
	sc, ok := streamByName[name]
	if !ok {
		return nil, fmt.Errorf("unknown compression layer %q", name)
	}
	return sc.newReader(r), nil
}

// NewWriter wraps w in the named codec's streaming encoder.
func NewWriter(name string, w io.Writer) (StreamWriter, error) {
	sc, ok := streamByName[name]
	if !ok {
		return nil, fmt.Errorf("unknown compression layer %q", name)
	}
	return sc.newWriter(w), nil
}

// NewWriterLevel is NewWriter with a compression level where the codec
// has one (bzip2 -1..-9); other levels fall back to the codec default,
// as the whole-buffer CompressLevel does.
func NewWriterLevel(name string, w io.Writer, level int) (StreamWriter, error) {
	sc, ok := streamByName[name]
	if !ok {
		return nil, fmt.Errorf("unknown compression layer %q", name)
	}
	if sc.level != nil && level >= 1 && level <= 9 {
		return sc.level(w, level), nil
	}
	return sc.newWriter(w), nil
}
