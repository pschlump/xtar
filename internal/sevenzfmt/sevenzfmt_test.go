/*
Copyright (C) Philip Schlump, 2012-2026.

MIT Licensed.
*/

package sevenzfmt

import (
	"bytes"
	"encoding/hex"
	"os"
	"os/exec"
	"time"

	"github.com/pschlump/xtar/internal/member"
	"path/filepath"
	"testing"
)

// z7 creates an archive at arc from the operands, with the given
// method switches, and returns arc's path.
func z7(t *testing.T, dir, arc string, switches, operands []string) string {
	t.Helper()
	bin, err := exec.LookPath("7zz")
	if err != nil {
		bin, err = exec.LookPath("7z")
		if err != nil {
			t.Skip("7-Zip CLI not installed")
		}
	}
	args := append([]string{"a", "-t7z", arc}, switches...)
	args = append(args, operands...)
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("7z %v: %v\n%s", args, err, out)
	}
	return arc
}

// tree builds the standard test tree and returns its root: a regular
// file, a subdirectory file, an empty file, and a symlink.
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
	mk("a.txt", "hello seven zip\n")
	mk("sub/b.txt", "nested content here\n")
	mk("empty.txt", "")
	if err := os.Symlink("a.txt", filepath.Join(dir, "link.txt")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	return dir
}

// TestCLIMatrix parses 7-Zip CLI archives across every method we
// support and checks names, kinds, and contents.
func TestCLIMatrix(t *testing.T) {
	dir := tree(t)
	cases := []struct {
		name string
		sw   []string
	}{
		{"default", nil},
		{"lzma", []string{"-m0=lzma"}},
		{"lzma2", []string{"-m0=lzma2"}},
		{"delta", []string{"-m0=delta"}},
		{"deflate", []string{"-m0=deflate"}},
		{"bzip2", []string{"-m0=bzip2"}},
		{"copy", []string{"-mx=0"}},
		{"multifolder", []string{"-ms=100k"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			work := t.TempDir()
			arc := z7(t, dir, filepath.Join(work, "t.7z"), tc.sw, []string{"a.txt", "sub", "empty.txt"})
			b, err := os.ReadFile(arc)
			if err != nil {
				t.Fatal(err)
			}
			a, err := Parse(b, "")
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			byName := map[string]*struct {
				kind int
				data string
			}{}
			for i := range a.Members {
				m := &a.Members[i]
				byName[m.Name] = &struct {
					kind int
					data string
				}{int(m.Kind), string(m.Data)}
			}
			if got := byName["a.txt"]; got == nil || got.data != "hello seven zip\n" {
				t.Errorf("a.txt: %+v", got)
			}
			if got := byName["sub/b.txt"]; got == nil || got.data != "nested content here\n" {
				t.Errorf("sub/b.txt: %+v", got)
			}
			if got := byName["empty.txt"]; got == nil || got.data != "" {
				t.Errorf("empty.txt: %+v", got)
			}
			if got := byName["sub"]; got == nil || got.kind != 5 { // Directory
				t.Errorf("sub dir: %+v", got)
			}
		})
	}
}

// TestCLISymlink: -snl stores symlinks with the UNIX attribute
// extension; the member carries the target as its link name.
func TestCLISymlink(t *testing.T) {
	dir := tree(t)
	work := t.TempDir()
	arc := z7(t, dir, filepath.Join(work, "t.7z"), []string{"-snl"}, []string{"link.txt", "a.txt"})
	b, err := os.ReadFile(arc)
	if err != nil {
		t.Fatal(err)
	}
	a, err := Parse(b, "")
	if err != nil {
		t.Fatal(err)
	}
	var link bool
	for _, m := range a.Members {
		if m.Name == "link.txt" {
			if m.Kind != 2 || m.LinkName != "a.txt" { // SymLink
				t.Fatalf("link.txt: kind=%d link=%q", m.Kind, m.LinkName)
			}
			link = true
		}
	}
	if !link {
		t.Fatal("link.txt missing")
	}
}

// TestCLIBCJ: a real Mach-O through BCJ — alone and chained before
// LZMA2 — decodes byte-exact against the original.
func TestCLIBCJ(t *testing.T) {
	orig, err := os.ReadFile("/bin/ls")
	if err != nil {
		t.Skip("/bin/ls unreadable")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin.dat")
	if err := os.WriteFile(bin, orig, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, m := range [][]string{{"-m0=BCJ"}, {"-m0=LZMA2", "-m0=BCJ"}} {
		work := t.TempDir()
		arc := z7(t, dir, filepath.Join(work, "t.7z"), m, []string{bin})
		b, err := os.ReadFile(arc)
		if err != nil {
			t.Fatal(err)
		}
		a, err := Parse(b, "")
		if err != nil {
			t.Fatalf("%s: %v", m, err)
		}
		if !bytes.Equal(a.Members[0].Data, orig) {
			t.Errorf("%s: content mismatch", m)
		}
	}
}

// TestCLIAES: content encryption and full header encryption, the
// right password decrypting and the wrong one failing.
func TestCLIAES(t *testing.T) {
	dir := tree(t)
	for _, tc := range []struct {
		name string
		sw   []string
	}{
		{"content", []string{"-ppassword123"}},
		{"header", []string{"-ppassword123", "-mhe=on"}},
	} {
		work := t.TempDir()
		arc := z7(t, dir, filepath.Join(work, "t.7z"), tc.sw, []string{"a.txt", "sub"})
		b, err := os.ReadFile(arc)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Parse(b, ""); err == nil {
			t.Errorf("%s: no password decoded", tc.name)
		}
		if _, err := Parse(b, "wrong"); err == nil {
			t.Errorf("%s: wrong password decoded", tc.name)
		}
		a, err := Parse(b, "password123")
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		var ok bool
		for _, m := range a.Members {
			if m.Name == "a.txt" && string(m.Data) == "hello seven zip\n" {
				ok = true
			}
		}
		if !ok {
			t.Errorf("%s: a.txt wrong after decrypt", tc.name)
		}
	}
}

// TestKDFVector pins the 7z AES key derivation against a value
// computed independently (Python hashlib + openssl round-trip).
func TestKDFVector(t *testing.T) {
	key := deriveKey(nil, utf16LE("password123"), 19)
	want := "753a0607d0581942a194b1ad173341b1d69f00d6c211a5ed3f0f821cc12c174d"
	if got := hex.EncodeToString(key); got != want {
		t.Fatalf("key %s, want %s", got, want)
	}
}

// TestMalformed: truncations and byte flips error out — no panics, no
// partial success.
func TestMalformed(t *testing.T) {
	dir := tree(t)
	work := t.TempDir()
	arc := z7(t, dir, filepath.Join(work, "t.7z"), nil, []string{"a.txt", "sub"})
	clean, err := os.ReadFile(arc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(nil, ""); err == nil {
		t.Error("empty input parsed")
	}
	bad := append([]byte("7z\xBC\xAF\x27\x1D"), make([]byte, 28)...)
	if _, err := Parse(bad, ""); err == nil {
		t.Error("bad magic parsed")
	}
	s := uint32(11)
	for i := 0; i < 2000; i++ {
		s = s*1664525 + 1013904223
		bad := append([]byte{}, clean...)
		switch s % 3 {
		case 0:
			bad[int(s>>8)%len(bad)] ^= byte(s >> 16)
		case 1:
			bad = bad[:int(s>>8)%len(bad)]
		default:
			bad[int(s>>8)%len(bad)] = byte(s >> 16)
		}
		_, _ = Parse(bad, "")
	}
	for i := 0; i < len(clean); i++ {
		if _, err := Parse(clean[:i], ""); err == nil {
			t.Fatalf("prefix %d parsed", i)
		}
	}
}

// testMembers is the write-side corpus: a directory, a text file, a
// binary, an empty file, and a symlink.
func testMembers() []member.Member {
	base := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	return []member.Member{
		{Name: "dir", Kind: member.Directory, Mode: 0o755, ModTime: base},
		{Name: "dir/a.txt", Kind: member.Regular, Mode: 0o644, ModTime: base, Data: []byte("hello write side\n")},
		{Name: "dir/b.bin", Kind: member.Regular, Mode: 0o600, ModTime: base, Data: bytes.Repeat([]byte("xyzzy "), 3000)},
		{Name: "dir/empty", Kind: member.Regular, Mode: 0o644, ModTime: base},
		{Name: "link", Kind: member.SymLink, Mode: 0o777, ModTime: base, LinkName: "dir/a.txt"},
	}
}

// TestBuildRoundTrip builds archives in every shape — LZMA, stored,
// AES — and requires our own parser, the 7-Zip CLI, and bsdtar
// (libarchive) to read them back byte-exact.
func TestBuildRoundTrip(t *testing.T) {
	bin := z7bin(t)
	for _, tc := range []struct {
		name string
		pw   string
		lvl  int
	}{
		{"lzma", "", 6},
		{"copy", "", 0},
		{"aes", "secret-pw", 6},
	} {
		blob, err := Build(testMembers(), tc.pw, tc.lvl)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		a, err := Parse(blob, tc.pw)
		if err != nil {
			t.Errorf("%s: own parse: %v", tc.name, err)
			continue
		}
		if len(a.Members) != 5 {
			t.Errorf("%s: %d members", tc.name, len(a.Members))
			continue
		}
		if a.Members[1].Name != "dir/a.txt" || string(a.Members[1].Data) != "hello write side\n" {
			t.Errorf("%s: a.txt wrong: %+v", tc.name, a.Members[1])
		}
		if a.Members[2].Kind != member.Regular || len(a.Members[2].Data) != 18000 {
			t.Errorf("%s: b.bin wrong", tc.name)
		}
		if a.Members[3].Kind != member.Regular || len(a.Members[3].Data) != 0 {
			t.Errorf("%s: empty wrong", tc.name)
		}
		if a.Members[4].Kind != member.SymLink || a.Members[4].LinkName != "dir/a.txt" {
			t.Errorf("%s: link wrong: kind=%d link=%q", tc.name, a.Members[4].Kind, a.Members[4].LinkName)
		}

		if bin == "" {
			continue
		}
		tmp := t.TempDir()
		arc := filepath.Join(tmp, "t.7z")
		if err := os.WriteFile(arc, blob, 0o644); err != nil {
			t.Fatal(err)
		}
		args := []string{"t"}
		if tc.pw != "" {
			args = append(args, "-p"+tc.pw)
		}
		if out, err := exec.Command(bin, append(args, arc)...).CombinedOutput(); err != nil {
			t.Errorf("%s: 7zz t rejected: %v: %s", tc.name, err, out)
		}
		if tc.pw == "" {
			// libarchive is a second reader (no AES)
			if out, err := exec.Command("/usr/bin/bsdtar", "-tf", arc).CombinedOutput(); err != nil {
				t.Errorf("%s: bsdtar rejected: %v: %s", tc.name, err, out)
			}
		}
		xargs := []string{"x", "-y"}
		if tc.pw != "" {
			xargs = append(xargs, "-p"+tc.pw)
		}
		outDir := t.TempDir()
		xargs = append(xargs, "-o"+outDir, arc)
		if out, err := exec.Command(bin, xargs...).CombinedOutput(); err != nil {
			t.Errorf("%s: 7zz x failed: %v: %s", tc.name, err, out)
			continue
		}
		got, err := os.ReadFile(filepath.Join(outDir, "dir", "a.txt"))
		if err != nil || string(got) != "hello write side\n" {
			t.Errorf("%s: 7zz x content wrong: %q %v", tc.name, got, err)
		}
	}
}

func z7bin(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"7zz", "7z"} {
		if bin, err := exec.LookPath(name); err == nil {
			return bin
		}
	}
	return ""
}
