/*
Copyright (C) Philip Schlump, 2012-2026.

BSD 3 Clause Licensed.
*/

package eng

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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

func TestCreateUnsupportedExtension(t *testing.T) {
	tree(t)
	_, err := Create(&CreateOpts{
		Path:             filepath.Join(t.TempDir(), "a.tar.xz"),
		DefaultContainer: "tar",
		Walk:             walkFiles([]string{"proj"}),
	})
	if err == nil || !strings.Contains(err.Error(), "xz") {
		t.Fatalf("want xz unsupported error, got %v", err)
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
	// vanishes.
	dst2 := filepath.Join(t.TempDir(), "strip")
	if err := Extract(a, &ExtractOpts{Dest: dst2, Strip: 1, Warn: func(string) {}}); err != nil {
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
	a, err := OpenFile(out, "")
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
