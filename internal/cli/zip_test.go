/*
Copyright (C) Philip Schlump, 2012-2026.

BSD 3 Clause Licensed.
*/

package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pschlump/xtar/internal/eng"
)

func TestZipRoundTrip(t *testing.T) {
	src, work := cliTree(t)
	t.Chdir(src)
	arc := filepath.Join(work, "a.zip")

	if code := Zip("zip", []string{"-r", arc, "proj"}); code != exitOK {
		t.Fatalf("create exit %d", code)
	}
	a := openArchive(t, arc)
	if a.Format != "zip" || len(a.Members) != 4 { // proj, a.txt, sub, b.txt
		t.Fatalf("archive: format=%s members=%v", a.Format, namesOf(a))
	}
	if code := Unzip("unzip", []string{"-l", arc}); code != exitOK {
		t.Fatalf("unzip -l exit %d", code)
	}
	if code := Zipinfo("zipinfo", []string{"-1", arc}); code != exitOK {
		t.Fatalf("zipinfo -1 exit %d", code)
	}
	dst := filepath.Join(work, "out")
	if code := Unzip("unzip", []string{"-q", "-o", arc, "-d", dst}); code != exitOK {
		t.Fatalf("unzip exit %d", code)
	}
	got, err := os.ReadFile(filepath.Join(dst, "proj/sub/b.txt"))
	if err != nil || string(got) != "beta\n" {
		t.Fatalf("content %q %v", got, err)
	}
}

func TestZipUpdateDeleteTest(t *testing.T) {
	src, work := cliTree(t)
	t.Chdir(src)
	arc := filepath.Join(work, "a.zip")
	if code := Zip("zip", []string{"-r", arc, "proj"}); code != exitOK {
		t.Fatalf("create exit %d", code)
	}
	if code := Zip("zip", []string{arc, "proj/a.txt"}); code != exitOK {
		t.Fatalf("update exit %d", code)
	}
	if code := Zip("zip", []string{"-T", arc}); code != exitOK {
		t.Fatalf("test exit %d", code)
	}
	if code := Zip("zip", []string{"-d", arc, "*a.txt"}); code != exitOK {
		t.Fatalf("delete exit %d", code)
	}
	a := openArchive(t, arc)
	for _, m := range a.Members {
		if strings.HasSuffix(m.Name, "a.txt") {
			t.Fatalf("a.txt survived -d: %v", namesOf(a))
		}
	}
}

func TestZipEncryption(t *testing.T) {
	src, work := cliTree(t)
	t.Chdir(src)
	arc := filepath.Join(work, "e.zip")
	if code := Zip("zip", []string{"-r", "-P", "pw", arc, "proj"}); code != exitOK {
		t.Fatalf("create exit %d", code)
	}
	// Directory entries stay unencrypted; files need the password.
	if _, err := eng.OpenFile(arc, "pw"); err != nil {
		t.Fatalf("open with password: %v", err)
	}
	dst := filepath.Join(work, "out")
	if code := Unzip("unzip", []string{"-q", "-o", "-P", "pw", arc, "-d", dst}); code != exitOK {
		t.Fatalf("unzip exit %d", code)
	}
	got, err := os.ReadFile(filepath.Join(dst, "proj/a.txt"))
	if err != nil || string(got) != "alpha\n" {
		t.Fatalf("content %q %v", got, err)
	}
	// Wrong password is fatal.
	if code := Unzip("unzip", []string{"-q", "-o", "-P", "bad", arc, "-d", filepath.Join(work, "x")}); code != exitFatal {
		t.Fatalf("wrong password exit %d", code)
	}
}

func TestUnzipFlattenAndPromptless(t *testing.T) {
	src, work := cliTree(t)
	t.Chdir(src)
	arc := filepath.Join(work, "a.zip")
	if code := Zip("zip", []string{"-r", arc, "proj"}); code != exitOK {
		t.Fatalf("create exit %d", code)
	}
	dst := filepath.Join(work, "flat")
	if code := Unzip("unzip", []string{"-q", "-o", "-j", arc, "-d", dst}); code != exitOK {
		t.Fatalf("junk extract exit %d", code)
	}
	if _, err := os.Stat(filepath.Join(dst, "b.txt")); err != nil {
		t.Fatal("flattened member missing")
	}
	// Without a terminal to answer the replace prompt, re-extraction
	// skips existing files with a warning.
	if code := Unzip("unzip", []string{"-q", "-j", arc, "-d", dst}); code != exitWarn {
		t.Fatalf("promptless re-extract exit %d", code)
	}
	// -o makes it silent.
	if code := Unzip("unzip", []string{"-q", "-o", "-j", arc, "-d", dst}); code != exitOK {
		t.Fatalf("-o re-extract exit %d", code)
	}
}

// TestCrossDialectMatrix is the core promise: any dialect reads any
// container.
func TestCrossDialectMatrix(t *testing.T) {
	src, work := cliTree(t)
	t.Chdir(src)

	z := filepath.Join(work, "a.zip")
	tr := filepath.Join(work, "b.tar")
	if code := Zip("zip", []string{"-r", z, "proj"}); code != exitOK {
		t.Fatalf("zip create exit %d", code)
	}
	if code := Tar("tar", []string{"-cf", tr, "proj"}); code != exitOK {
		t.Fatalf("tar create exit %d", code)
	}

	// tar reads zip
	out := filepath.Join(work, "t-from-z")
	if code := Tar("tar", []string{"-xf", z, "-C", out}); code != exitOK {
		t.Fatalf("tar -xf zip exit %d", code)
	}
	checkContent(t, filepath.Join(out, "proj/a.txt"))

	// unzip reads tar
	out = filepath.Join(work, "u-from-t")
	if code := Unzip("unzip", []string{"-q", "-o", tr, "-d", out}); code != exitOK {
		t.Fatalf("unzip tar exit %d", code)
	}
	checkContent(t, filepath.Join(out, "proj/a.txt"))

	// cpio reads zip
	out = filepath.Join(work, "c-from-z")
	if code := runCpioIn(t, out, "-id", "-F", z); code != exitOK {
		t.Fatalf("cpio -i zip exit %d", code)
	}
	checkContent(t, filepath.Join(out, "proj/a.txt"))

	// 7z reads and writes all of it
	lz := filepath.Join(work, "c.tar.gz")
	if code := Tar("tar", []string{"-czf", lz, "proj"}); code != exitOK {
		t.Fatalf("tar -czf exit %d", code)
	}
	out = filepath.Join(work, "7-from-tgz")
	if code := Sevenz("7z", []string{"x", "-y", "-o" + out, lz}); code != exitOK {
		t.Fatalf("7z x tar.gz exit %d", code)
	}
	checkContent(t, filepath.Join(out, "proj/a.txt"))
}

func TestSevenzCommands(t *testing.T) {
	src, work := cliTree(t)
	t.Chdir(src)
	arc := filepath.Join(work, "a.zip")

	if code := Sevenz("7z", []string{"a", arc, "proj"}); code != exitOK {
		t.Fatalf("7z a exit %d", code)
	}
	if code := Sevenz("7z", []string{"l", arc}); code != exitOK {
		t.Fatalf("7z l exit %d", code)
	}
	if code := Sevenz("7z", []string{"t", arc}); code != exitOK {
		t.Fatalf("7z t exit %d", code)
	}
	out := filepath.Join(work, "x")
	if code := Sevenz("7z", []string{"x", "-y", "-o" + out, arc}); code != exitOK {
		t.Fatalf("7z x exit %d", code)
	}
	checkContent(t, filepath.Join(out, "proj/a.txt"))

	flat := filepath.Join(work, "e")
	if code := Sevenz("7z", []string{"e", "-y", "-o" + flat, arc}); code != exitOK {
		t.Fatalf("7z e exit %d", code)
	}
	if _, err := os.Stat(filepath.Join(flat, "a.txt")); err != nil {
		t.Fatal("flat extract missing a.txt")
	}
	if code := Sevenz("7z", []string{"d", arc, "*a.txt"}); code != exitOK {
		t.Fatalf("7z d exit %d", code)
	}
	a := openArchive(t, arc)
	for _, m := range a.Members {
		if strings.HasSuffix(m.Name, "a.txt") {
			t.Fatalf("a.txt survived 7z d")
		}
	}
	if code := Sevenz("7z", []string{"nope", arc}); code != exitFatal {
		t.Fatalf("unknown command exit %d", code)
	}
	// 7z creates by extension too.
	tr := filepath.Join(work, "s.tar")
	if code := Sevenz("7z", []string{"a", tr, "proj"}); code != exitOK {
		t.Fatalf("7z a tar exit %d", code)
	}
	if a := openArchive(t, tr); a.Format != "tar" {
		t.Fatalf("7z a .tar wrote %s", a.Format)
	}
}

// TestSystemZipInterop checks both directions against the system zip,
// unzip, and zipinfo when they exist.
func TestSystemZipInterop(t *testing.T) {
	sysZip, err1 := exec.LookPath("zip")
	sysUnzip, err2 := exec.LookPath("unzip")
	sysZipinfo, err3 := exec.LookPath("zipinfo")
	if err1 != nil || err2 != nil || err3 != nil {
		t.Skip("system zip tools not available")
	}
	src, work := cliTree(t)
	t.Chdir(src)

	ours := filepath.Join(work, "ours.zip")
	if code := Zip("zip", []string{"-r", ours, "proj"}); code != exitOK {
		t.Fatalf("create exit %d", code)
	}
	out, err := exec.Command(sysUnzip, "-t", ours).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "No errors detected") {
		t.Fatalf("system unzip cannot test ours: %v\n%s", err, out)
	}
	out, err = exec.Command(sysZipinfo, "-1", ours).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "proj/a.txt") {
		t.Fatalf("system zipinfo cannot list ours: %v\n%s", err, out)
	}

	theirs := filepath.Join(work, "theirs.zip")
	cmd := exec.Command(sysZip, "-r", "-P", "pw", theirs, "proj")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("system zip create: %v\n%s", err, out)
	}
	dst := filepath.Join(work, "from-theirs")
	if code := Unzip("unzip", []string{"-q", "-o", "-P", "pw", theirs, "-d", dst}); code != exitOK {
		t.Fatalf("unzip system encrypted exit %d", code)
	}
	checkContent(t, filepath.Join(dst, "proj/a.txt"))

	// Our encrypted archive decrypts with the system unzip too.
	enc := filepath.Join(work, "enc.zip")
	if code := Zip("zip", []string{"-r", "-P", "pw", enc, "proj"}); code != exitOK {
		t.Fatalf("encrypted create exit %d", code)
	}
	dst2 := filepath.Join(work, "sys-dec")
	if out, err := exec.Command(sysUnzip, "-q", "-o", "-P", "pw", enc, "-d", dst2).CombinedOutput(); err != nil {
		t.Fatalf("system unzip cannot decrypt ours: %v\n%s", err, out)
	}
	checkContent(t, filepath.Join(dst2, "proj/a.txt"))
}

func checkContent(t *testing.T, path string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "alpha\n" {
		t.Fatalf("%s: content %q %v", path, got, err)
	}
}

// TestZipLZMAZstdCreate: the dialect writes -Z lzma and -Z zstd, and
// the system 7zz verifies both archives.
func TestZipLZMAZstdCreate(t *testing.T) {
	bin := ""
	for _, n := range []string{"7zz", "7z"} {
		if p, err := exec.LookPath(n); err == nil {
			bin = p
			break
		}
	}
	if bin == "" {
		t.Skip("no system 7z")
	}
	src, work := cliTree(t)
	t.Chdir(src)
	big := filepath.Join(src, "proj", "big.txt")
	if err := os.WriteFile(big, bytes.Repeat([]byte("the quick brown fox. "), 500), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{"lzma", "zstd"} {
		out := filepath.Join(work, "m-"+m+".zip")
		if code := Zip("zip", []string{"-Z", m, "-r", out, "proj"}); code != exitOK {
			t.Fatalf("-Z %s: exit %d", m, code)
		}
		if o, err := exec.Command(bin, "t", out).CombinedOutput(); err != nil {
			t.Fatalf("-Z %s: system 7z rejected: %v\n%s", m, err, o)
		}
		dst := filepath.Join(work, "x-"+m)
		if o, err := exec.Command(bin, "x", "-y", "-o"+dst, out).CombinedOutput(); err != nil {
			t.Fatalf("-Z %s: system 7z extract: %v\n%s", m, err, o)
		}
		got, err := os.ReadFile(filepath.Join(dst, "proj", "big.txt"))
		if err != nil || !bytes.Equal(got, bytes.Repeat([]byte("the quick brown fox. "), 500)) {
			t.Fatalf("-Z %s: content mismatch", m)
		}
	}
}
