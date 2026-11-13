/*
Copyright (C) Philip Schlump, 2012-2026.

BSD 3 Clause Licensed.
*/

package walk

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func mkTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	d := filepath.Join(root, "d")
	for _, p := range []string{
		filepath.Join(d, "f.txt"),
		filepath.Join(d, "sub", "g.txt"),
	} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(p), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func names(t *testing.T, o *Opts) []string {
	t.Helper()
	if !o.Recurse && !o.NoRecursion {
		o.Recurse = true
	}
	mems, err := Gather(o)
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	var out []string
	for _, m := range mems {
		out = append(out, m.Name)
	}
	sort.Strings(out)
	return out
}

func wantNames(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("members = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("members = %v, want %v", got, want)
		}
	}
}

// TestNamesRelativeToC: a -C style operand names members from the
// operand as typed (the base), not from the joined filesystem path —
// "-C d ." reads d/ but stores "." and "./f.txt", the GNU tar shape.
func TestNamesRelativeToC(t *testing.T) {
	root := mkTree(t)
	d := filepath.Join(root, "d")

	got := names(t, &Opts{Files: []string{d}, Names: []string{"."}, NamePolicy: TarNames})
	wantNames(t, got, []string{".", "./f.txt", "./sub", "./sub/g.txt"})

	// An absolute filesystem path with a relative base works the same.
	got = names(t, &Opts{Files: []string{d}, Names: []string{"pkg"}, NamePolicy: TarNames})
	wantNames(t, got, []string{"pkg", "pkg/f.txt", "pkg/sub", "pkg/sub/g.txt"})
}

// TestNamePolicy: tar keeps names as typed (including a "." root
// member and "./" prefixes) and strips leading ".."; zip strips "./"
// and drops the "." root; cpio keeps everything.
func TestNamePolicy(t *testing.T) {
	root := mkTree(t)

	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)

	got := names(t, &Opts{Files: []string{"d"}, NamePolicy: TarNames})
	wantNames(t, got, []string{"d", "d/f.txt", "d/sub", "d/sub/g.txt"})

	// Without a Names entry the base is the operand itself, so a bare
	// "." walks the working tree as ".", "./f.txt", ...
	if err := os.Chdir(filepath.Join(root, "d")); err != nil {
		t.Fatal(err)
	}
	got = names(t, &Opts{Files: []string{"."}, NamePolicy: TarNames})
	wantNames(t, got, []string{".", "./f.txt", "./sub", "./sub/g.txt"})

	got = names(t, &Opts{Files: []string{"."}}) // zip style: no root, no "./"
	wantNames(t, got, []string{"f.txt", "sub", "sub/g.txt"})

	got = names(t, &Opts{Files: []string{"./f.txt"}, NamePolicy: TarNames})
	wantNames(t, got, []string{"./f.txt"})

	got = names(t, &Opts{Files: []string{"./f.txt"}})
	wantNames(t, got, []string{"f.txt"})
}

// TestDotDotStripped: GNU tar strips leading ".." components from
// member names (with one-time notices); "-C d/sub .." stores "." and
// "f.txt".  cpio keeps them verbatim.
func TestDotDotStripped(t *testing.T) {
	root := mkTree(t)
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(filepath.Join(root, "d", "sub")); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)

	var notices []string
	got := names(t, &Opts{
		Files:      []string{".."},
		NamePolicy: TarNames,
		Notice:     func(s string) { notices = append(notices, s) },
	})
	wantNames(t, got, []string{".", "f.txt", "sub", "sub/g.txt"})
	if len(notices) < 1 || !strings.Contains(strings.Join(notices, " "), "..") {
		t.Fatalf("notices = %v, want a leading-.. notice", notices)
	}

	notices = nil
	got = names(t, &Opts{
		Files:      []string{".."},
		NamePolicy: CpioNames,
		Notice:     func(s string) { notices = append(notices, s) },
	})
	wantNames(t, got, []string{"..", "../f.txt", "../sub", "../sub/g.txt"})
	if len(notices) != 0 {
		t.Fatalf("cpio notices = %v, want none", notices)
	}
}

// TestAbsoluteStripped: every policy strips a leading "/" (with the
// one-time notice), the way GNU tar does.
func TestAbsoluteStripped(t *testing.T) {
	root := mkTree(t)
	abs := filepath.Join(root, "d", "f.txt")
	var notices []string
	got := names(t, &Opts{
		Files:      []string{abs},
		NamePolicy: TarNames,
		Notice:     func(s string) { notices = append(notices, s) },
	})
	wantNames(t, got, []string{strings.TrimPrefix(filepath.ToSlash(abs), "/")})
	if len(notices) != 1 {
		t.Fatalf("notices = %v, want one leading-slash notice", notices)
	}
}
