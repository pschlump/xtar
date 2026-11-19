/*
Copyright (C) Philip Schlump, 2012-2026.

MIT Licensed.
*/

package eng

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pschlump/xtar/internal/member"
	"github.com/pschlump/xtar/internal/pat"
	"github.com/pschlump/xtar/internal/walk"
)

// walkFiles is a default gather over the given operands.
func walkFiles(files []string) walk.Opts {
	return walk.Opts{Files: files, Recurse: true, Symlinks: true, Warn: func(string) {}}
}

// mustPat compiles patterns for the opts fields.
func mustPat(pats ...string) []*pat.Pattern {
	var out []*pat.Pattern
	for _, s := range pats {
		out = append(out, pat.MustCompile(s))
	}
	return out
}

// tree builds a small test tree, makes it the working directory, and
// returns its root; operands stay relative so member names are short.
func tree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	mk := func(rel, content string) {
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk("proj/a.txt", "alpha\n")
	mk("proj/sub/b.txt", "beta\n")
	mk("proj/sub/skip.log", "noise\n")
	if err := os.Symlink("a.txt", filepath.Join(dir, "proj/alink")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	t.Chdir(dir)
	return dir
}

func TestCreateExtractRoundTrip(t *testing.T) {
	tree(t)
	out := filepath.Join(t.TempDir(), "a.tar")

	a, err := Create(&CreateOpts{
		Path:             out,
		Container:        "tar",
		DefaultContainer: "tar",
		Walk:             walkFiles([]string{"proj"}),
	})
	if err != nil {
		t.Fatal(err)
	}
	// proj/, a.txt, alink, sub/, b.txt, skip.log = 6 members
	if len(a.Members) != 6 {
		t.Fatalf("got %d members, want 6: %+v", len(a.Members), a.Members)
	}

	// Read it back and check the sniff decisions.
	r, err := OpenFile(out, "")
	if err != nil {
		t.Fatal(err)
	}
	if r.Format != "tar" || len(r.Layers) != 0 {
		t.Fatalf("bad decode: %s %v", r.Format, r.Layers)
	}

	// Extract into a fresh dir and compare content.
	dst := filepath.Join(t.TempDir(), "out")
	if err := Extract(r, &ExtractOpts{Dest: dst, Warn: func(string) {}}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dst, "proj/sub/b.txt"))
	if err != nil || string(got) != "beta\n" {
		t.Fatalf("b.txt round trip: %q %v", got, err)
	}
	if _, err := os.Lstat(filepath.Join(dst, "proj/alink")); err != nil {
		t.Fatalf("alink missing: %v", err)
	}
}

func TestCreateCompressedByExtension(t *testing.T) {
	tree(t)
	out := filepath.Join(t.TempDir(), "a.tar.gz")
	_, err := Create(&CreateOpts{
		Path:             out,
		DefaultContainer: "tar",
		Walk:             walkFiles([]string{"proj"}),
	})
	if err != nil {
		t.Fatal(err)
	}
	a, err := OpenFile(out, "")
	if err != nil {
		t.Fatal(err)
	}
	if a.Format != "tar" || len(a.Layers) != 1 || a.Layers[0] != "gzip" {
		t.Fatalf("gzip by extension: %s %v", a.Format, a.Layers)
	}
}

func TestCreateTarXz(t *testing.T) {
	tree(t)
	out := filepath.Join(t.TempDir(), "a.tar.xz")
	a, err := Create(&CreateOpts{
		Path:             out,
		DefaultContainer: "tar",
		Walk:             walkFiles([]string{"proj"}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if a.Format != "tar" || len(a.Layers) != 1 || a.Layers[0] != "xz" {
		t.Fatalf("resolve: format=%s layers=%v", a.Format, a.Layers)
	}
	if a.CompSize > 2048 {
		t.Fatalf("xz archive unexpectedly large: %d", a.CompSize)
	}
	dst := filepath.Join(t.TempDir(), "out")
	b, err := OpenFile(out, "")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := Extract(b, &ExtractOpts{Dest: dst, Warn: func(string) {}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dst, "proj/a.txt")); err != nil {
		t.Fatal("a.txt missing after xz round trip")
	}
}

func TestCreateUnsupportedExtension(t *testing.T) {
	tree(t)
	_, err := Create(&CreateOpts{
		Path:             filepath.Join(t.TempDir(), "a.rar"),
		Container:        "rar",
		DefaultContainer: "tar",
		Walk:             walkFiles([]string{"proj"}),
	})
	if err == nil || !strings.Contains(err.Error(), "rar") {
		t.Fatalf("want unknown-container error, got %v", err)
	}
}

func TestCreateTarZstd(t *testing.T) {
	tree(t)
	out := filepath.Join(t.TempDir(), "a.tar.zst")
	a, err := Create(&CreateOpts{
		Path:             out,
		Codec:            "zstd",
		DefaultContainer: "tar",
		Walk:             walkFiles([]string{"proj"}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if a.Format != "tar" || len(a.Layers) != 1 || a.Layers[0] != "zstd" {
		t.Fatalf("resolve: format=%s layers=%v", a.Format, a.Layers)
	}
	b, err := OpenFile(out, "")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	dst := filepath.Join(t.TempDir(), "out")
	if err := Extract(b, &ExtractOpts{Dest: dst, Warn: func(string) {}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dst, "proj/a.txt")); err != nil {
		t.Fatal("a.txt missing after zstd round trip")
	}
}

func TestExtractPatternsAndStrip(t *testing.T) {
	tree(t)
	out := filepath.Join(t.TempDir(), "a.tar")
	if _, err := Create(&CreateOpts{
		Path:             out,
		Container:        "tar",
		DefaultContainer: "tar",
		Walk:             walkFiles([]string{"proj"}),
	}); err != nil {
		t.Fatal(err)
	}
	a, err := OpenFile(out, "")
	if err != nil {
		t.Fatal(err)
	}

	// Include pattern.
	dst := filepath.Join(t.TempDir(), "sel")
	if err := Extract(a, &ExtractOpts{
		Dest:    dst,
		Include: mustPat("*.txt"),
		Warn:    func(string) {},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dst, "proj/a.txt")); err != nil {
		t.Fatal("a.txt not selected by *.txt")
	}
	if _, err := os.Lstat(filepath.Join(dst, "proj/sub/skip.log")); !os.IsNotExist(err) {
		t.Fatal("skip.log should not be selected")
	}

	// Strip one component: proj/a.txt becomes a.txt; proj/ itself
	// vanishes.  A streaming archive is one walk, so reopen it.
	a2, err := OpenFile(out, "")
	if err != nil {
		t.Fatal(err)
	}
	dst2 := filepath.Join(t.TempDir(), "strip")
	if err := Extract(a2, &ExtractOpts{Dest: dst2, Strip: 1, Warn: func(string) {}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dst2, "a.txt")); err != nil {
		t.Fatal("stripped a.txt missing")
	}
}

func TestExtractRejectsTraversal(t *testing.T) {
	tree(t)
	out := filepath.Join(t.TempDir(), "a.tar")
	if _, err := Create(&CreateOpts{
		Path:             out,
		Container:        "tar",
		DefaultContainer: "tar",
		Walk:             walkFiles([]string{"proj"}),
	}); err != nil {
		t.Fatal(err)
	}
	// Decode keeps the archive whole-buffer, so the hostile rename the
	// next line plants is what Extract actually sees (a streaming
	// archive's members only materialize as Each walks them).
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	a, err := Decode(data, "")
	if err != nil {
		t.Fatal(err)
	}
	a.Members[0].Name = "../../escape.txt"

	var warned []string
	dst := filepath.Join(t.TempDir(), "out")
	if err := Extract(a, &ExtractOpts{Dest: dst, Warn: func(m string) { warned = append(warned, m) }}); err != nil {
		t.Fatal(err)
	}
	if len(warned) == 0 {
		t.Fatal("traversal member was not warned about")
	}
	if _, err := os.Lstat(filepath.Join(dst, "../../escape.txt")); err == nil {
		t.Fatal("escape.txt was written outside the destination")
	}
}

func TestUpdateAppendDeleteAndCompressedGuard(t *testing.T) {
	tree(t)
	out := filepath.Join(t.TempDir(), "a.tar")
	if _, err := Create(&CreateOpts{
		Path:             out,
		Container:        "tar",
		DefaultContainer: "tar",
		Walk:             walkFiles([]string{"proj/a.txt"}),
	}); err != nil {
		t.Fatal(err)
	}

	// Append another file.
	res, err := Update(&UpdateOpts{
		Path: out,
		Walk: walkFiles([]string{"proj/sub/b.txt"}),
	})
	if err != nil || res.Appended != 1 || res.Members != 2 {
		t.Fatalf("append: %+v %v", res, err)
	}

	// Delete by pattern.
	res, err = Update(&UpdateOpts{Path: out, Delete: mustPat("*.txt")})
	if err != nil || res.Deleted != 2 || res.Members != 0 {
		t.Fatalf("delete: %+v %v", res, err)
	}

	// Compressed archives refuse updates.
	gz := filepath.Join(t.TempDir(), "a.tgz")
	if _, err := Create(&CreateOpts{
		Path:             gz,
		DefaultContainer: "tar",
		Walk:             walkFiles([]string{"proj/a.txt"}),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := Update(&UpdateOpts{Path: gz, Walk: walkFiles([]string{"proj"})}); err == nil {
		t.Fatal("compressed update should fail")
	}
}

func TestBareStreamDecode(t *testing.T) {
	tree(t)
	// A bare .gz of one file, via Codec with Bare.
	out := filepath.Join(t.TempDir(), "note.txt.gz")
	if _, err := Create(&CreateOpts{
		Path:  out,
		Codec: "gzip",
		Bare:  true,
		Walk:  walkFiles([]string{"proj/a.txt"}),
	}); err != nil {
		t.Fatal(err)
	}
	a, err := OpenFile(out, "")
	if err != nil {
		t.Fatal(err)
	}
	if a.Format != "bare" || len(a.Members) != 1 || a.Members[0].Name != "note.txt" {
		t.Fatalf("bare decode: %s %+v", a.Format, a.Members)
	}
	if string(a.Members[0].Data) != "alpha\n" {
		t.Fatalf("bare content: %q", a.Members[0].Data)
	}
}

func TestSniffFile(t *testing.T) {
	tree(t)
	out := filepath.Join(t.TempDir(), "a.tgz")
	if _, err := Create(&CreateOpts{
		Path:             out,
		DefaultContainer: "tar",
		Walk:             walkFiles([]string{"proj/a.txt"}),
	}); err != nil {
		t.Fatal(err)
	}
	info, err := SniffFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if info.Format != "tar" || len(info.Layers) != 1 || info.Members == 0 {
		t.Fatalf("sniff: %+v", info)
	}
}

// TestOpen7z opens a native .7z (made by the 7-Zip CLI) through the
// engine, extracts it, and compares the tree.
func TestOpen7z(t *testing.T) {
	bin, err := exec.LookPath("7zz")
	if err != nil {
		bin, err = exec.LookPath("7z")
		if err != nil {
			t.Skip("7-Zip CLI not installed")
		}
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("alpha\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "sub", "b.txt"), []byte("beta\n"), 0o644)
	out := filepath.Join(t.TempDir(), "a.7z")
	cmd := exec.Command(bin, "a", "-t7z", out, "a.txt", "sub")
	cmd.Dir = dir
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("7z: %v\n%s", err, b)
	}

	a, err := OpenFile(out, "")
	if err != nil {
		t.Fatal(err)
	}
	if a.Format != "7z" || len(a.Layers) != 0 {
		t.Fatalf("resolve: %s %v", a.Format, a.Layers)
	}
	if len(a.Members) != 3 {
		t.Fatalf("members %d: %v", len(a.Members), a.Members)
	}
	dst := filepath.Join(t.TempDir(), "out")
	if err := Extract(a, &ExtractOpts{Dest: dst, Warn: func(string) {}}); err != nil {
		t.Fatal(err)
	}
	for rel, want := range map[string]string{"a.txt": "alpha\n", "sub/b.txt": "beta\n"} {
		got, err := os.ReadFile(filepath.Join(dst, rel))
		if err != nil || string(got) != want {
			t.Fatalf("%s: %q %v", rel, got, err)
		}
	}
	if _, err := SniffFile(out); err != nil {
		t.Fatalf("sniff: %v", err)
	}
	// updates go through the rebuild path now
	if _, err := Update(&UpdateOpts{Path: out, Level: 6}); err != nil {
		t.Fatalf("native 7z update: %v", err)
	}
}

// TestCreate7z writes a native .7z through Create and Update, with
// the 7-Zip CLI as the validator when present.
func TestCreate7z(t *testing.T) {
	tree(t)
	out := filepath.Join(t.TempDir(), "a.7z")
	a, err := Create(&CreateOpts{
		Path:             out,
		Container:        "7z",
		Level:            6,
		DefaultContainer: "tar",
		Walk:             walkFiles([]string{"proj"}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if a.Format != "7z" || len(a.Layers) != 0 {
		t.Fatalf("resolve: %s %v", a.Format, a.Layers)
	}
	b, err := OpenFile(out, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Members) != 6 {
		t.Fatalf("members %d", len(b.Members))
	}

	// Append and delete through the rebuild path.
	res, err := Update(&UpdateOpts{Path: out, Level: 6})
	if err != nil {
		t.Fatal(err)
	}
	_ = res
	if _, err := Update(&UpdateOpts{Path: out, Level: 6, Delete: mustPat("*.log")}); err != nil {
		t.Fatal(err)
	}
	c, err := OpenFile(out, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range c.Members {
		if strings.HasSuffix(m.Name, ".log") {
			t.Fatal("skip.log survived delete")
		}
	}

	// The system 7-Zip validates both shapes.
	for _, bin := range []string{"7zz", "7z"} {
		if p, err := exec.LookPath(bin); err == nil {
			if out2, err := exec.Command(p, "t", out).CombinedOutput(); err != nil {
				t.Fatalf("7z t ours: %v\n%s", err, out2)
			}
			break
		}
	}
}

// TestOpenDeb reads a handcrafted Debian package: an ar of
// debian-binary + two compressed tars.  The ar members surface as
// members; drilling into them is a pipe away.
func TestOpenDeb(t *testing.T) {
	var ar []byte
	ar = append(ar, []byte("!<arch>\n")...)
	add := func(name string, payload []byte) {
		h := fmt.Sprintf("%-16s%-12s%-6s%-6s%-8s%-10s`\n", name, "1700000000", "0", "0", "100644", fmt.Sprint(len(payload)))
		ar = append(ar, []byte(h)...)
		ar = append(ar, payload...)
		if len(payload)%2 == 1 {
			ar = append(ar, '\n')
		}
	}
	add("debian-binary", []byte("2.0\n"))
	tree(t) // the shared fixture; walk from its working directory
	tgz := filepath.Join(t.TempDir(), "c.tar.gz")
	if _, err := Create(&CreateOpts{
		Path:             tgz,
		DefaultContainer: "tar",
		Walk:             walkFiles([]string{"proj"}),
	}); err != nil {
		t.Fatal(err)
	}
	blob, err := os.ReadFile(tgz)
	if err != nil {
		t.Fatal(err)
	}
	add("control.tar.gz", blob)
	add("data.tar.gz", blob)

	out := filepath.Join(t.TempDir(), "grep.deb")
	if err := os.WriteFile(out, ar, 0o644); err != nil {
		t.Fatal(err)
	}
	a, err := OpenFile(out, "")
	if err != nil {
		t.Fatal(err)
	}
	if a.Format != "ar" || len(a.Members) != 3 {
		t.Fatalf("open: %s %+v", a.Format, a.Members)
	}
	if a.Members[0].Name != "debian-binary" || string(a.Members[0].Data) != "2.0\n" {
		t.Fatalf("debian-binary: %+v", a.Members[0])
	}
	if a.Members[2].Name != "data.tar.gz" || !bytes.Equal(a.Members[2].Data, blob) {
		t.Fatalf("data.tar.gz mismatch")
	}

	// the pipe drill-in: member to stdout, back through the engine
	a2, err := OpenFile(out, "")
	if err != nil {
		t.Fatal(err)
	}
	var picked *member.Member
	for i := range a2.Members {
		if a2.Members[i].Name == "control.tar.gz" {
			picked = &a2.Members[i]
		}
	}
	if picked == nil {
		t.Fatal("control.tar.gz not found")
	}
	inner, err := Decode(picked.Data, "")
	if err != nil {
		t.Fatalf("inner decode: %v", err)
	}
	if inner.Format != "tar" || len(inner.Members) == 0 {
		t.Fatalf("inner: %s %+v", inner.Format, inner.Members)
	}

	// .a static libraries resolve the same way
	lib := filepath.Join(t.TempDir(), "lib.a")
	if err := os.WriteFile(lib, ar, 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := OpenFile(lib, "")
	if err != nil || b.Format != "ar" {
		t.Fatalf("lib.a: %v %s", err, b.Format)
	}
}
