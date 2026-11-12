/*
Copyright (C) Philip Schlump, 2012-2026.

BSD 3 Clause Licensed.
*/

package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pschlump/xtar/internal/eng"
)

func cliTree(t *testing.T) (src, work string) {
	t.Helper()
	src = t.TempDir()
	work = t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "proj/sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "proj/a.txt"), []byte("alpha\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "proj/sub/b.txt"), []byte("beta\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return src, work
}

func TestTarCreateListExtract(t *testing.T) {
	src, work := cliTree(t)
	t.Chdir(src)
	arc := filepath.Join(work, "a.tar")

	if code := Tar("tar", []string{"-cf", arc, "proj"}); code != exitOK {
		t.Fatalf("create exit %d", code)
	}
	if code := Tar("tar", []string{"-tf", arc}); code != exitOK {
		t.Fatalf("list exit %d", code)
	}
	dst := filepath.Join(work, "out")
	if code := Tar("tar", []string{"-xf", arc, "-C", dst}); code != exitOK {
		t.Fatalf("extract exit %d", code)
	}
	got, err := os.ReadFile(filepath.Join(dst, "proj/sub/b.txt"))
	if err != nil || string(got) != "beta\n" {
		t.Fatalf("b.txt: %q %v", got, err)
	}
}

func TestTarStyleArgumentSpellings(t *testing.T) {
	src, work := cliTree(t)
	// Old-style dashless bundle, a bundled short group, and an
	// attached long form — three spellings of the same create.
	for _, args := range [][]string{
		{"cf", filepath.Join(work, "a.tar"), filepath.Join(src, "proj")},
		{"-cf", filepath.Join(work, "b.tar"), filepath.Join(src, "proj")},
		{"--create", "--file=" + filepath.Join(work, "c.tar"), filepath.Join(src, "proj")},
	} {
		if code := Tar("tar", args); code != exitOK {
			t.Fatalf("%v: exit %d", args, code)
		}
	}
}

func TestTarExitCodes(t *testing.T) {
	if code := Tar("tar", nil); code != exitFatal {
		t.Fatalf("no-op argv should be fatal, got %d", code)
	}
	if code := Tar("tar", []string{"-cf", filepath.Join(t.TempDir(), "a.tar")}); code != exitFatal {
		t.Fatalf("empty archive should be fatal, got %d", code)
	}
	if code := Tar("tar", []string{"-q"}); code != exitFatal {
		t.Fatalf("unknown option should be fatal, got %d", code)
	}
	if code := Tar("tar", []string{"-Jcf", filepath.Join(t.TempDir(), "no.xz"), "x"}); code != exitFatal {
		t.Fatalf("xz should be a clear fatal, got %d", code)
	}
}

func TestTarUpdateFamily(t *testing.T) {
	src, work := cliTree(t)
	arc := filepath.Join(work, "a.tar")
	if code := Tar("tar", []string{"-cf", arc, filepath.Join(src, "proj/a.txt")}); code != exitOK {
		t.Fatalf("create exit %d", code)
	}
	if code := Tar("tar", []string{"-rf", arc, filepath.Join(src, "proj/sub")}); code != exitOK {
		t.Fatalf("append exit %d", code)
	}
	if code := Tar("tar", []string{"-f", arc, "--delete", "*a.txt"}); code != exitOK {
		t.Fatalf("delete exit %d", code)
	}

	// Compressed archives refuse -r the way GNU tar does.
	tgz := filepath.Join(work, "a.tgz")
	if code := Tar("tar", []string{"-czf", tgz, filepath.Join(src, "proj")}); code != exitOK {
		t.Fatalf("create gz exit %d", code)
	}
	if code := Tar("tar", []string{"-rf", tgz, filepath.Join(src, "proj")}); code != exitFatal {
		t.Fatalf("compressed append should be fatal, got %d", code)
	}
}

func TestTarTransform(t *testing.T) {
	src, work := cliTree(t)
	t.Chdir(src) // relative operands keep the anchored pattern meaningful
	arc := filepath.Join(work, "a.tar")
	if code := Tar("tar", []string{"-cf", arc, "--transform", "s/^proj/renamed/", "proj"}); code != exitOK {
		t.Fatalf("create exit %d", code)
	}
	a, err := eng.OpenFile(arc, "")
	if err != nil {
		t.Fatal(err)
	}
	if a.Members[0].Name != "renamed" {
		t.Fatalf("transform did not apply: %q", a.Members[0].Name)
	}

	if code := Tar("tar", []string{"-cf", filepath.Join(work, "b.tar"), "--transform", "s/a/X", "proj"}); code != exitOK {
		t.Fatalf("create exit %d", code)
	}
	if code := Tar("tar", []string{"-cf", filepath.Join(work, "c.tar"), "--transform", "y/a/X/", "proj"}); code != exitFatal {
		t.Fatalf("non-s transform should be fatal, got %d", code)
	}
}

func TestXtarVerbs(t *testing.T) {
	src, work := cliTree(t)
	t.Chdir(src)
	arc := filepath.Join(work, "a.tar.gz")
	if code := Xtar("xtar", []string{"c", arc, "proj"}); code != exitOK {
		t.Fatalf("xtar c exit %d", code)
	}
	if code := Xtar("xtar", []string{"--sniff", arc}); code != exitOK {
		t.Fatalf("xtar --sniff exit %d", code)
	}
	dst := filepath.Join(work, "out")
	if code := Xtar("xtar", []string{"x", arc, "-C", dst}); code != exitOK {
		t.Fatalf("xtar x exit %d", code)
	}
	got, err := os.ReadFile(filepath.Join(dst, "proj/a.txt"))
	if err != nil || string(got) != "alpha\n" {
		t.Fatalf("xtar x content: %q %v", got, err)
	}
	if code := Xtar("xtar", []string{"nope", arc}); code != exitFatal {
		t.Fatalf("unknown verb should be fatal, got %d", code)
	}
}
