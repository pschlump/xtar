/*
Copyright (C) Philip Schlump, 2012-2026.

BSD 3 Clause Licensed.
*/

package eng

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/pschlump/xtar/internal/cpiofmt"
	"github.com/pschlump/xtar/internal/layer"
	"github.com/pschlump/xtar/internal/member"
	"github.com/pschlump/xtar/internal/sevenzfmt"
	"github.com/pschlump/xtar/internal/tarfmt"
	"github.com/pschlump/xtar/internal/walk"
	"github.com/pschlump/xtar/internal/zipfmt"
)

// CreateOpts is the whole create operation, dialect-independent.
type CreateOpts struct {
	Path             string // "-" writes to stdout
	Container        string // explicit container override ("tar","cpio","zip"); "" resolves by name
	Codec            string // explicit codec override; "" resolves by name
	Bare             bool   // create a bare compressed stream of one input (7z -t gzip)
	Level            int    // codec level when the codec has one
	DefaultContainer string // dialect default when the name carries no container suffix
	TarFormat        string // gnu | ustar | pax | v7
	CpioFormat       string // newc | crc | odc
	ZipMethod        int    // zipfmt.Method*: -1 (unset) defaults to deflate
	ZipPassword      string
	ZipComment       string
	EmptyOK          bool
	Walk             walk.Opts
}

// Create gathers members and writes the archive, choosing container
// and codec from the output name unless the opts override them.  It
// returns the archive description (for verify and messages).
//
// The write side streams: tar and cpio members go through the format
// writers and the compression layer straight to the file (or stdout),
// so the container and compressed bytes never sit in memory — only
// the gathered members do, bounded by the largest file.  zip still
// materializes (its central directory is written last); a bare stream
// is the one file's bytes through the codec.
func Create(o *CreateOpts) (*Archive, error) {
	container, codec := o.Container, o.Codec
	if container == "" {
		res, err := ResolveByName(o.Path, o.DefaultContainer)
		if err != nil {
			return nil, err
		}
		container = res.Container
		if codec == "" {
			codec = res.Codec
		}
	}
	if o.Bare {
		container = ""
		if codec == "" {
			return nil, errors.New("bare stream output needs an explicit compression type")
		}
	}

	mems, err := walk.Gather(&o.Walk)
	if err != nil {
		return nil, err
	}
	if len(mems) == 0 && !o.EmptyOK {
		return nil, errors.New("refusing to create an empty archive (no files were selected)")
	}

	// Pre-flight the names (against io.Discard, before the output file
	// is created) so a bad format or codec leaves nothing behind, the
	// way GNU tar validates before opening its output.
	cpioVariant := defaultStr(o.CpioFormat, "newc")
	switch container {
	case "tar":
		if _, err := tarfmt.NewWriter(io.Discard, o.TarFormat); err != nil {
			return nil, err
		}
	case "cpio":
		if _, err := cpiofmt.NewWriter(io.Discard, cpioVariant); err != nil {
			return nil, err
		}
	case "zip", "":
	case "7z":
	default:
		return nil, fmt.Errorf("unknown container format %q", container)
	}
	if codec != "" {
		if _, err := layer.NewWriterLevel(codec, io.Discard, o.Level); err != nil {
			return nil, err
		}
	}

	a := &Archive{Path: o.Path, Members: mems}
	var zipBlob []byte
	switch container {
	case "tar":
		a.Format = "tar"
		a.Variant = defaultStr(o.TarFormat, "gnu")
	case "cpio":
		a.Format = "cpio"
		a.Variant = cpioVariant
	case "7z":
		blob, err := sevenzfmt.Build(mems, o.ZipPassword, o.Level)
		if err != nil {
			return nil, err
		}
		zipBlob = blob
		a.Format = "7z"
	case "zip":
		method := o.ZipMethod
		if method < 0 {
			method = int(zipfmt.MethodDeflate)
		}
		for i := range mems {
			mems[i].Method = uint16(method)
			// Like Info-ZIP, directory entries are never encrypted.
			if o.ZipPassword != "" && mems[i].Kind != member.Directory {
				mems[i].Encrypted = true
			}
		}
		zipBlob, err = zipfmt.Build(mems, o.ZipComment, o.ZipPassword)
		if err != nil {
			return nil, err
		}
		a.Format = "zip"
		a.Variant = ""
	case "":
		if len(mems) != 1 {
			return nil, errors.New("a bare compressed stream holds exactly one file")
		}
		a.Format = "bare"
	}

	// Open the output, count what leaves, wrap the codec around it.
	var out io.Writer = os.Stdout
	var closeFile func() error
	if o.Path != "-" {
		f, err := os.Create(o.Path)
		if err != nil {
			return nil, err
		}
		out = f
		closeFile = f.Close
	}
	cw := &countWriter{w: out}
	sink := io.Writer(cw)
	var sw layer.StreamWriter
	if codec != "" {
		sw, err = layer.NewWriterLevel(codec, cw, o.Level)
		if err != nil {
			if closeFile != nil {
				_ = closeFile() // teardown on the way to an error return
			}
			return nil, err
		}
		sink = sw
		a.Layers = []string{codec}
	}

	// Stream the container.  An error mid-archive leaves a partial
	// output file (the GNU tar behavior), reported as the failure.
	switch container {
	case "tar":
		tw, err := tarfmt.NewWriter(sink, o.TarFormat)
		if err == nil {
			for i := range mems {
				if err = tw.WriteMember(&mems[i]); err != nil {
					break
				}
			}
			if err == nil {
				err = tw.Close()
			}
		}
		if err != nil {
			if closeFile != nil {
				_ = closeFile() // teardown on the way to an error return
			}
			return nil, err
		}
	case "cpio":
		cw2, err := cpiofmt.NewWriter(sink, cpioVariant)
		if err == nil {
			for i := range mems {
				if err = cw2.WriteMember(&mems[i]); err != nil {
					break
				}
			}
			if err == nil {
				err = cw2.Close()
			}
		}
		if err != nil {
			if closeFile != nil {
				_ = closeFile() // teardown on the way to an error return
			}
			return nil, err
		}
	case "zip", "7z":
		if _, err := sink.Write(zipBlob); err != nil {
			if closeFile != nil {
				_ = closeFile() // teardown on the way to an error return
			}
			return nil, err
		}
	case "":
		if _, err := sink.Write(mems[0].Data); err != nil {
			if closeFile != nil {
				_ = closeFile() // teardown on the way to an error return
			}
			return nil, err
		}
	}

	// Finish the compression stream and the file.
	if sw != nil {
		if err := sw.Close(); err != nil {
			if closeFile != nil {
				_ = closeFile() // teardown on the way to an error return
			}
			return nil, err
		}
	}
	if closeFile != nil {
		if err := closeFile(); err != nil {
			return nil, err
		}
	}
	a.CompSize = cw.n
	return a, nil
}

// countWriter counts the bytes that leave, for CompSize reporting.
type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

func defaultStr(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
