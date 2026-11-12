/*
Copyright (C) Philip Schlump, 2012-2026.

BSD 3 Clause Licensed.
*/

package eng

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/pschlump/xtar/internal/cpiofmt"
	"github.com/pschlump/xtar/internal/layer"
	"github.com/pschlump/xtar/internal/tarfmt"
	"github.com/pschlump/xtar/internal/walk"
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
	ZipMethod        uint16 // 0 store, 8 deflate, 12 bzip2
	ZipPassword      string
	ZipComment       string
	EmptyOK          bool
	Walk             walk.Opts
}

// Create gathers members and writes the archive, choosing container
// and codec from the output name unless the opts override them.  It
// returns the archive description (for verify and messages).
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

	var blob []byte
	a := &Archive{Path: o.Path, Members: mems}
	switch container {
	case "tar":
		blob, err = tarfmt.Build(o.TarFormat, mems)
		a.Format = "tar"
		a.Variant = defaultStr(o.TarFormat, "gnu")
	case "cpio":
		blob, err = cpiofmt.Build(defaultStr(o.CpioFormat, "newc"), mems)
		a.Format = "cpio"
		a.Variant = defaultStr(o.CpioFormat, "newc")
	case "zip":
		return nil, fmt.Errorf("%s archives are not supported yet — see the README roadmap", container)
	case "":
		if len(mems) != 1 {
			return nil, errors.New("a bare compressed stream holds exactly one file")
		}
		blob = mems[0].Data
		a.Format = "bare"
	default:
		return nil, fmt.Errorf("unknown container format %q", container)
	}
	if err != nil {
		return nil, err
	}

	if codec != "" {
		blob, err = layer.CompressLevel(codec, blob, o.Level)
		if err != nil {
			return nil, err
		}
		a.Layers = []string{codec}
	}
	a.CompSize = int64(len(blob))

	if o.Path == "-" {
		_, err = io.Copy(os.Stdout, bytes.NewReader(blob))
		return a, err
	}
	if err := os.WriteFile(o.Path, blob, 0o666); err != nil {
		return nil, err
	}
	return a, nil
}

func defaultStr(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
