/*
Copyright (C) Philip Schlump, 2012-2026.

MIT Licensed.
*/

package cli

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pschlump/xtar/internal/eng"
	"github.com/pschlump/xtar/internal/member"
)

// withStdin feeds s to the dialect's stdin for the duration of the test
// (cpio -o/-p read their name list from there).
func withStdin(t *testing.T, s string) {
	t.Helper()
	f, err := os.CreateTemp("", "cpio-stdin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = f
	t.Cleanup(func() {
		os.Stdin = old
		f.Close()
		os.Remove(f.Name())
	})
}

// runCpioIn runs the cpio dialect from inside dir (created on demand):
// copy-in always extracts relative to the working directory.
func runCpioIn(t *testing.T, dir string, args ...string) int {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(old) })
	return Cpio("cpio", args)
}

// openArchive opens path and materializes its members (a streaming
// archive only accumulates them as Each walks it).
func openArchive(t *testing.T, path string) *eng.Archive {
	t.Helper()
	a, err := eng.OpenFile(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Each(func(m *member.Member, data io.Reader) error {
		if m.Kind == member.Regular && m.Data == nil {
			if _, err := io.ReadAll(data); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestCpioCreateListExtract(t *testing.T) {
	src, work := cliTree(t)
	t.Chdir(src)
	arc := filepath.Join(work, "a.cpio")

	withStdin(t, "proj\nproj/a.txt\nproj/sub\nproj/sub/b.txt\n")
	if code := Cpio("cpio", []string{"-o", "-F", arc}); code != exitOK {
		t.Fatalf("create exit %d", code)
	}
	withStdin(t, "")
	if code := Cpio("cpio", []string{"-it", "-F", arc}); code != exitOK {
		t.Fatalf("list exit %d", code)
	}
	dst := filepath.Join(work, "out")
	if code := runCpioIn(t, dst, "-id", "-F", arc); code != exitOK {
		t.Fatalf("extract exit %d", code)
	}
	got, err := os.ReadFile(filepath.Join(dst, "proj/sub/b.txt"))
	if err != nil || string(got) != "beta\n" {
		t.Fatalf("content %q %v", got, err)
	}
}

func TestCpioFormats(t *testing.T) {
	src, work := cliTree(t)
	t.Chdir(src)
	for _, format := range []string{"newc", "crc", "odc"} {
		arc := filepath.Join(work, "a."+format)
		withStdin(t, "proj/a.txt\n")
		if code := Cpio("cpio", []string{"-o", "-H", format, "-F", arc}); code != exitOK {
			t.Fatalf("%s create exit %d", format, code)
		}
		dst := filepath.Join(work, "x-"+format)
		if code := runCpioIn(t, dst, "-idm", "-F", arc); code != exitOK {
			t.Fatalf("%s extract exit %d", format, code)
		}
		got, err := os.ReadFile(filepath.Join(dst, "proj/a.txt"))
		if err != nil || string(got) != "alpha\n" {
			t.Fatalf("%s: content %q %v", format, got, err)
		}
	}
	// -H ustar writes a tar the tar dialect can read.
	tarArc := filepath.Join(work, "a.tar")
	withStdin(t, "proj/a.txt\n")
	if code := Cpio("cpio", []string{"-o", "-H", "ustar", "-F", tarArc}); code != exitOK {
		t.Fatalf("ustar create exit %d", code)
	}
	if code := Tar("tar", []string{"-tf", tarArc}); code != exitOK {
		t.Fatalf("tar list of cpio -H ustar exit %d", code)
	}
	// binary is read-only
	withStdin(t, "proj/a.txt\n")
	if code := Cpio("cpio", []string{"-o", "-H", "bin", "-F", filepath.Join(work, "no")}); code != exitFatal {
		t.Fatalf("-H bin should be fatal, got %d", code)
	}
}

// TestCpioFindListNoRecursion: the canonical `find | cpio -o` flow
// lists directories and their children explicitly.  cpio must archive
// each name exactly once — no recursion, no duplicate-member warnings.
func TestCpioFindListNoRecursion(t *testing.T) {
	src, work := cliTree(t)
	t.Chdir(src)
	arc := filepath.Join(work, "a.cpio")

	withStdin(t, "proj\nproj/a.txt\nproj/sub\nproj/sub/b.txt\n")
	if code := Cpio("cpio", []string{"-o", "-F", arc}); code != exitOK {
		t.Fatalf("create exit %d", code)
	}
	withStdin(t, "")
	if code := Cpio("cpio", []string{"-it", "-F", arc}); code != exitOK {
		t.Fatalf("list exit %d", code)
	}
	a := openArchive(t, arc)
	want := map[string]bool{"proj": true, "proj/a.txt": true, "proj/sub": true, "proj/sub/b.txt": true}
	if len(a.Members) != len(want) {
		t.Fatalf("got %d members, want %d: %v", len(a.Members), len(want), namesOf(a))
	}
	for _, m := range a.Members {
		if !want[m.Name] {
			t.Fatalf("unexpected member %q", m.Name)
		}
	}
}

func namesOf(a *eng.Archive) []string {
	out := make([]string, len(a.Members))
	for i, m := range a.Members {
		out[i] = m.Name
	}
	return out
}

func TestCpioNoDirsSkipWarning(t *testing.T) {
	src, work := cliTree(t)
	t.Chdir(src)
	arc := filepath.Join(work, "a.cpio")
	withStdin(t, "proj/a.txt\n")
	if code := Cpio("cpio", []string{"-o", "-F", arc}); code != exitOK {
		t.Fatalf("create exit %d", code)
	}
	// Fresh destination, no -d: members under missing parents are
	// skipped with warnings → exit 1.
	dst := filepath.Join(work, "out")
	if code := runCpioIn(t, dst, "-i", "-F", arc); code != exitWarn {
		t.Fatalf("no -d extract should warn, got %d", code)
	}
}

// TestCpioReextractSilent: with -m the mtimes are restored, so a
// second extraction over the same tree must be quiet and exit 0 (the
// OvIfOlder default compares at container mtime precision, and only
// for regular files).
func TestCpioReextractSilent(t *testing.T) {
	src, work := cliTree(t)
	t.Chdir(src)
	arc := filepath.Join(work, "a.cpio")
	withStdin(t, "proj\nproj/a.txt\nproj/sub\nproj/sub/b.txt\n")
	if code := Cpio("cpio", []string{"-o", "-F", arc}); code != exitOK {
		t.Fatalf("create exit %d", code)
	}
	dst := filepath.Join(work, "out")
	for i := 0; i < 2; i++ {
		if code := runCpioIn(t, dst, "-idm", "-F", arc); code != exitOK {
			t.Fatalf("extract %d exit %d", i, code)
		}
	}
}

func TestCpioAppend(t *testing.T) {
	src, work := cliTree(t)
	t.Chdir(src)
	arc := filepath.Join(work, "a.cpio")
	withStdin(t, "proj/a.txt\n")
	if code := Cpio("cpio", []string{"-o", "-F", arc}); code != exitOK {
		t.Fatalf("create exit %d", code)
	}
	withStdin(t, "proj/sub/b.txt\n")
	if code := Cpio("cpio", []string{"-oA", "-F", arc}); code != exitOK {
		t.Fatalf("append exit %d", code)
	}
	a := openArchive(t, arc)
	if len(a.Members) != 2 || a.Members[1].Name != "proj/sub/b.txt" {
		t.Fatalf("append produced %v", namesOf(a))
	}
}

func TestCpioPassThrough(t *testing.T) {
	src, work := cliTree(t)
	t.Chdir(src)
	dst := filepath.Join(work, "dst")
	withStdin(t, "proj\nproj/a.txt\nproj/sub\nproj/sub/b.txt\n")
	if code := Cpio("cpio", []string{"-p", "-d", dst}); code != exitOK {
		t.Fatalf("pass-through exit %d", code)
	}
	got, err := os.ReadFile(filepath.Join(dst, "proj/sub/b.txt"))
	if err != nil || string(got) != "beta\n" {
		t.Fatalf("pass-through content %q %v", got, err)
	}
}

func TestCpioPatterns(t *testing.T) {
	src, work := cliTree(t)
	t.Chdir(src)
	arc := filepath.Join(work, "a.cpio")
	withStdin(t, "proj\nproj/a.txt\nproj/sub\nproj/sub/b.txt\n")
	if code := Cpio("cpio", []string{"-o", "-F", arc}); code != exitOK {
		t.Fatalf("create exit %d", code)
	}
	// Include only *.txt, letting -d create the directories.
	dst := filepath.Join(work, "inc")
	if code := runCpioIn(t, dst, "-id", "-F", arc, "*.txt"); code != exitOK {
		t.Fatalf("include extract exit %d", code)
	}
	if _, err := os.Stat(filepath.Join(dst, "proj/a.txt")); err != nil {
		t.Fatal("included member missing")
	}
	fi, err := os.Lstat(filepath.Join(dst, "proj/sub/b.txt"))
	if err != nil || fi.Mode().IsRegular() == false {
		t.Fatal("included nested member missing")
	}

	// -f inverts: everything except *.txt (the directories).
	dst2 := filepath.Join(work, "exc")
	if code := runCpioIn(t, dst2, "-id", "-f", "-F", arc, "*.txt"); code != exitOK {
		t.Fatalf("exclude extract exit %d", code)
	}
	if _, err := os.Stat(filepath.Join(dst2, "proj/a.txt")); err == nil {
		t.Fatal("excluded member extracted")
	}
	if _, err := os.Stat(filepath.Join(dst2, "proj/sub")); err != nil {
		t.Fatal("non-excluded directory missing")
	}
}

func TestCpioStdioRoundTrip(t *testing.T) {
	src, work := cliTree(t)
	t.Chdir(src)
	arc := filepath.Join(work, "a.cpio")
	withStdin(t, "proj/a.txt\n")
	if code := Cpio("cpio", []string{"-o", "-F", arc}); code != exitOK {
		t.Fatalf("create exit %d", code)
	}

	// No -F: copy-in reads the archive from stdin.
	f, err := os.Open(arc)
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = f
	code := Cpio("cpio", []string{"-it"})
	os.Stdin = old
	f.Close()
	if code != exitOK {
		t.Fatalf("stdin list exit %d", code)
	}
}

// TestCpioInterop runs the system cpio when present (macOS bsdcpio /
// GNU cpio): each side must read what the other writes.
func TestCpioInterop(t *testing.T) {
	sys, err := exec.LookPath("cpio")
	if err != nil {
		t.Skip("system cpio not available")
	}
	src, work := cliTree(t)
	t.Chdir(src)

	for _, format := range []string{"newc", "crc", "odc"} {
		arc := filepath.Join(work, "ours."+format)
		withStdin(t, "proj/a.txt\nproj/sub/b.txt\n")
		if code := Cpio("cpio", []string{"-o", "-H", format, "-F", arc}); code != exitOK {
			t.Fatalf("ours %s create exit %d", format, code)
		}
		out, err := exec.Command(sys, "-it", "-F", arc).CombinedOutput()
		if err != nil || !strings.Contains(string(out), "proj/a.txt") {
			t.Fatalf("system cpio cannot read our %s: %v\n%s", format, err, out)
		}
	}

	// System cpio writes newc, odc, and binary for us to read (macOS
	// bsdcpio can read crc but not write it).
	for _, tc := range []struct {
		name  string
		extra []string
	}{
		{"newc", nil}, {"odc", []string{"-H", "odc"}}, {"bin", []string{"-H", "bin"}},
	} {
		arc := filepath.Join(work, "sys."+tc.name)
		args := append([]string{"-o"}, tc.extra...)
		args = append(args, "-F", arc)
		cmd := exec.Command(sys, args...)
		cmd.Stdin = strings.NewReader("proj/a.txt\n")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("system cpio %s write: %v\n%s", tc.name, err, out)
		}
		withStdin(t, "")
		if code := Cpio("cpio", []string{"-it", "-F", arc}); code != exitOK {
			t.Fatalf("we cannot read system %s archive (exit %d)", tc.name, code)
		}
		dst := filepath.Join(work, "x-"+tc.name)
		if code := runCpioIn(t, dst, "-id", "-F", arc); code != exitOK {
			t.Fatalf("extract system %s exit %d", tc.name, code)
		}
		got, err := os.ReadFile(filepath.Join(dst, "proj/a.txt"))
		if err != nil || string(got) != "alpha\n" {
			t.Fatalf("system %s content %q %v", tc.name, got, err)
		}
	}

	// Cross-dialect: our tar reads our cpio, and the system tar too.
	oursNewc := filepath.Join(work, "ours.newc")
	if code := Tar("tar", []string{"-tf", oursNewc}); code != exitOK {
		t.Fatalf("our tar cannot list our newc: exit %d", code)
	}
	if out, err := exec.Command("tar", "-tf", oursNewc).CombinedOutput(); err != nil || !strings.Contains(string(out), "proj/a.txt") {
		t.Fatalf("system tar cannot list our newc: %v\n%s", err, out)
	}
}
