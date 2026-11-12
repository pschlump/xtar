/*
Copyright (C) Philip Schlump, 2012-2026.

BSD 3 Clause Licensed.
*/

package eng

import "strings"

// Resolved is the create-side decision made from an output file name.
type Resolved struct {
	Container string // "tar", "cpio", "zip", or the dialect default
	Codec     string // "", "gzip", "bzip2", "compress", "lz4"
}

func sfx(s, suffix string) bool   { return strings.HasSuffix(s, suffix) && len(s) > len(suffix) }
func trim(s string, n int) string { return s[:len(s)-n] }

// ResolveByName picks container and codec from the output name's
// suffixes — GNU tar's --auto-compress extended to containers, the
// bsdtar write-by-extension model.  Unsupported suffixes (.xz, .zst,
// .7z) are errors, not silent pass-throughs.
func ResolveByName(name, defaultContainer string) (Resolved, error) {
	r := Resolved{Container: defaultContainer}
	base := name
	if i := strings.LastIndexAny(base, "/\\"); i >= 0 {
		base = base[i+1:]
	}
	for {
		switch {
		case sfx(base, ".tgz"), sfx(base, ".taz"):
			r.Container, r.Codec, base = "tar", "gzip", trim(base, 4)
			continue
		case sfx(base, ".taZ"):
			r.Container, r.Codec, base = "tar", "compress", trim(base, 4)
			continue
		case sfx(base, ".tbz"), sfx(base, ".tz2"):
			r.Container, r.Codec, base = "tar", "bzip2", trim(base, 4)
			continue
		case sfx(base, ".tbz2"):
			r.Container, r.Codec, base = "tar", "bzip2", trim(base, 5)
			continue
		case sfx(base, ".txz"), sfx(base, ".xz"), sfx(base, ".lzma"):
			return r, UnsupportedError("xz")
		case sfx(base, ".tzst"), sfx(base, ".zst"):
			return r, UnsupportedError("zstd")
		case sfx(base, ".gz"):
			r.Codec, base = "gzip", trim(base, 3)
			continue
		case sfx(base, ".bz2"):
			r.Codec, base = "bzip2", trim(base, 4)
			continue
		case sfx(base, ".lz4"):
			r.Codec, base = "lz4", trim(base, 4)
			continue
		case sfx(base, ".Z"):
			r.Codec, base = "compress", trim(base, 2)
			continue
		case sfx(base, ".z"):
			r.Codec, base = "gzip", trim(base, 2)
			continue
		case sfx(base, ".tar"):
			r.Container, base = "tar", trim(base, 4)
		case sfx(base, ".cpio"):
			r.Container, base = "cpio", trim(base, 5)
		case sfx(base, ".zip"), sfx(base, ".jar"), sfx(base, ".war"), sfx(base, ".whl"):
			r.Container, base = "zip", trim(base, 4)
		case sfx(base, ".7z"):
			return r, UnsupportedError("7z")
		}
		break
	}
	return r, nil
}
