/*
Copyright (C) Philip Schlump, 2012-2026.

MIT Licensed.
*/

package eng

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pschlump/xtar/internal/cpiofmt"
	"github.com/pschlump/xtar/internal/layer"
	"github.com/pschlump/xtar/internal/member"
	"github.com/pschlump/xtar/internal/tarfmt"
)

// modTime makes a stable timestamp for the sample members.
func modTime(sec int64) time.Time { return time.Unix(sec, 0).UTC() }

// sampleMembers is a small mixed member set that exercises every
// data-carrying shape the streaming path must reproduce: regular data,
// a hard link, a symlink (whose Data is its target), and a directory.
func sampleMembers() []member.Member {
	base := int64(1700000000)
	return []member.Member{
		{Name: "d/", Kind: member.Directory, Mode: 0o755, ModTime: modTime(base)},
		{Name: "d/a.txt", Kind: member.Regular, Mode: 0o644, Size: 6, Data: []byte("alpha\n"), ModTime: modTime(base)},
		{Name: "d/b.bin", Kind: member.Regular, Mode: 0o644, Size: 3000, Data: bytes.Repeat([]byte{0xAB}, 3000), ModTime: modTime(base)},
		{Name: "d/link", Kind: member.HardLink, Mode: 0o644, LinkName: "d/a.txt", ModTime: modTime(base)},
		{Name: "d/sym", Kind: member.SymLink, Mode: 0o777, LinkName: "a.txt", ModTime: modTime(base)},
	}
}

// walked is what an Each visit collected about one member.
type walked struct {
	name string
	kind member.Kind
	size int64
	data []byte
}

// walkAll runs Each to completion and returns what it visited (regular
// data is read fully) plus the error.
func walkAll(a *Archive) ([]walked, error) {
	var out []walked
	err := a.Each(func(m *member.Member, data io.Reader) error {
		w := walked{name: m.Name, kind: m.Kind, size: m.DataSize()}
		if m.Kind == member.Regular {
			d, err := io.ReadAll(data)
			if err != nil {
				return err
			}
			w.data = d
		}
		out = append(out, w)
		return nil
	})
	return out, err
}

// TestOpenStreamMatchesDecode pins the streaming path against the
// whole-buffer one: every container, through every codec (and two
// nested), must yield the same members and bytes.
func TestOpenStreamMatchesDecode(t *testing.T) {
	bodies := map[string][]byte{}
	tar, err := tarfmt.Build("gnu", sampleMembers())
	if err != nil {
		t.Fatal(err)
	}
	bodies["tar"] = tar
	for _, v := range []string{"newc", "crc", "odc"} {
		c, err := cpiofmt.Build(v, sampleMembers())
		if err != nil {
			t.Fatal(err)
		}
		bodies["cpio/"+v] = c
	}

	wrappers := map[string][]string{
		"none":        nil,
		"gzip":        []string{"gzip"},
		"bzip2":       []string{"bzip2"},
		"compress":    []string{"compress"},
		"lz4":         []string{"lz4"},
		"nested":      []string{"gzip", "bzip2"}, // gzip(bzip2(body))
		"deep":        []string{"lz4", "gzip", "bzip2"},
		"wrong-order": []string{"bzip2", "gzip"},
	}
	for bname, body := range bodies {
		for wname, codecs := range wrappers {
			t.Run(bname+"/"+wname, func(t *testing.T) {
				blob := body
				for _, c := range codecs { // wrap outermost-first as written
					blob, err = layer.Compress(c, blob)
					if err != nil {
						t.Fatal(err)
					}
				}
				want, err := Decode(blob, "")
				if err != nil {
					t.Fatalf("whole-buffer decode: %v", err)
				}
				a, err := OpenStream(bytes.NewReader(blob), "test.bin", "")
				if err != nil {
					t.Fatalf("open: %v", err)
				}
				defer a.Close()
				if a.Format != want.Format || a.Variant != want.Variant {
					t.Fatalf("format/variant: got %s/%s want %s/%s", a.Format, a.Variant, want.Format, want.Variant)
				}
				if len(a.Layers) != len(want.Layers) {
					t.Fatalf("layers: got %v want %v", a.Layers, want.Layers)
				}
				got, err := walkAll(a)
				if err != nil {
					t.Fatalf("walk: %v", err)
				}
				if len(got) != len(want.Members) {
					t.Fatalf("member count: got %d want %d", len(got), len(want.Members))
				}
				for i, g := range got {
					w := want.Members[i]
					if g.name != w.Name || g.kind != w.Kind {
						t.Fatalf("member %d: got %s/%v want %s/%v", i, g.name, g.kind, w.Name, w.Kind)
					}
					if g.size != w.DataSize() {
						t.Fatalf("%s: size got %d want %d", g.name, g.size, w.DataSize())
					}
					if w.Kind == member.Regular && !bytes.Equal(g.data, w.Data) {
						t.Fatalf("%s: data differs", g.name)
					}
				}
			})
		}
	}
}

// TestEachSkipsUnreadData walks a streamed archive reading only part
// of the first member; the next member must still decode whole.
func TestEachSkipsUnreadData(t *testing.T) {
	body, err := tarfmt.Build("gnu", sampleMembers())
	if err != nil {
		t.Fatal(err)
	}
	a, err := OpenStream(bytes.NewReader(body), "a.tar", "")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	var second []byte
	err = a.Each(func(m *member.Member, data io.Reader) error {
		if m.Name == "d/a.txt" {
			buf := make([]byte, 2)
			if _, err := io.ReadFull(data, buf); err != nil {
				return err
			}
			return nil // leave the rest unread: Next must skip it
		}
		if m.Name == "d/b.bin" {
			d, err := io.ReadAll(data)
			if err != nil {
				return err
			}
			second = d
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(second, bytes.Repeat([]byte{0xAB}, 3000)) {
		t.Fatalf("member after skipped data is wrong (%d bytes)", len(second))
	}
}

// TestEachSingleWalk pins the one-walk rule: a streamed archive must be
// reopened, not walked twice.
func TestEachSingleWalk(t *testing.T) {
	body, err := tarfmt.Build("gnu", sampleMembers())
	if err != nil {
		t.Fatal(err)
	}
	a, err := OpenStream(bytes.NewReader(body), "a.tar", "")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if _, err := walkAll(a); err != nil {
		t.Fatal(err)
	}
	if _, err := walkAll(a); err == nil {
		t.Fatal("second walk should have failed")
	}
}

// TestOpenStreamTruncation checks that a stream cut inside the
// compressed layer or inside a member's data surfaces as an error from
// Each, the way whole-buffer Decode refuses the same bytes.  (A cut
// that lands mid-header or past the end marker is only a note, both
// paths — pinned separately in the tarfmt tests.)
func TestOpenStreamTruncation(t *testing.T) {
	// Incompressible member data, so a cut at a given fraction of the
	// gzip stream lands at that fraction of the tar.
	big := pseudoRandom(64 * 1024)
	body, err := tarfmt.Build("gnu", []member.Member{{
		Name: "big.bin", Kind: member.Regular, Mode: 0o644,
		Size: int64(len(big)), Data: big, ModTime: modTime(1700000000),
	}})
	if err != nil {
		t.Fatal(err)
	}
	gz, err := layer.Compress("gzip", body)
	if err != nil {
		t.Fatal(err)
	}

	// Cut the gzip stream inside the member's data (well past the 512
	// header, well before the end marker).
	cut := gz[:len(gz)*6/10]
	a, err := OpenStream(bytes.NewReader(cut), "a.tar.gz", "")
	if err != nil {
		t.Fatal(err) // opening is fine; the peel is lazy about content
	}
	defer a.Close()
	if _, err := walkAll(a); err == nil {
		t.Fatal("truncated gzip should fail during the walk")
	}
	if _, err := Decode(cut, ""); err == nil {
		t.Fatal("whole-buffer control: Decode should fail too")
	}

	// Uncompressed tar cut inside the member's data: both paths must
	// report it (the whole-buffer parse at open, the stream at the
	// member's Read).
	cutTar := body[:512+20000]
	a2, err := OpenStream(bytes.NewReader(cutTar), "a.tar", "")
	if err != nil {
		t.Fatal(err)
	}
	defer a2.Close()
	if _, err := walkAll(a2); err == nil {
		t.Fatal("truncated tar should fail during the walk")
	}
	if _, err := Decode(cutTar, ""); err == nil {
		t.Fatal("whole-buffer control: Decode should fail too")
	}
}

// pseudoRandom makes deterministic incompressible bytes (an LCG).
func pseudoRandom(n int) []byte {
	out := make([]byte, n)
	var s uint32 = 0x12345678
	for i := range out {
		s = s*1664525 + 1013904223
		out[i] = byte(s >> 23)
	}
	return out
}

// TestOpenStdinStream feeds a tar through a real pipe, the way
// `gtar cf - | xtar tf -` does.
func TestOpenStdinStream(t *testing.T) {
	body, err := tarfmt.Build("gnu", sampleMembers())
	if err != nil {
		t.Fatal(err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		w.Write(body)
		w.Close()
	}()
	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = old })

	a, err := OpenStdin("")
	if err != nil {
		r.Close()
		t.Fatal(err)
	}
	defer a.Close()
	if !a.Stdin {
		t.Fatal("Stdin flag not set")
	}
	got, err := walkAll(a)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(sampleMembers()) {
		t.Fatalf("members through the pipe: %d", len(got))
	}
	// The pipe writer must not block after we stop reading.
	r.Close()
}

// TestOpenFileCloseReleases exercises Close on a file-backed stream:
// after Close the file descriptor is gone even if the walk never ran.
func TestOpenFileCloseReleases(t *testing.T) {
	dir := t.TempDir()
	body, err := tarfmt.Build("gnu", sampleMembers())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "a.tar")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	a, err := OpenFile(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	// Closing twice must stay harmless (whole-buffer archives are a
	// no-op; the released stream reports nil).
	if err := a.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}
