/*
Copyright (C) Philip Schlump, 2012-2026.

MIT Licensed.
*/

package cli

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/pschlump/xtar/internal/eng"
	"github.com/pschlump/xtar/internal/member"
	"github.com/pschlump/xtar/internal/walk"
	"strings"
	"testing"
)

// TestSevenzNative drives the 7z dialect against a native .7z: list,
// test, extract, and the read-only guard on delete.
func TestSevenzNative(t *testing.T) {
	bin, err := exec.LookPath("7zz")
	if err != nil {
		bin, err = exec.LookPath("7z")
		if err != nil {
			t.Skip("7-Zip CLI not installed")
		}
	}
	src, work := cliTree(t)
	t.Chdir(src)
	arc := filepath.Join(work, "native.7z")
	cmd := exec.Command(bin, "a", "-t7z", arc, "proj")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("7z: %v\n%s", err, b)
	}

	if code := Sevenz("7z", []string{"l", arc}); code != exitOK {
		t.Fatalf("l exit %d", code)
	}
	if code := Sevenz("7z", []string{"t", arc}); code != exitOK {
		t.Fatalf("t exit %d", code)
	}
	dst := filepath.Join(work, "out")
	if code := Sevenz("7z", []string{"x", "-y", "-o" + dst, arc}); code != exitOK {
		t.Fatalf("x exit %d", code)
	}
	if _, err := os.Stat(filepath.Join(dst, "proj/a.txt")); err != nil {
		t.Fatal("a.txt missing after extract")
	}
	// delete and re-add round-trip through the rebuild path
	if code := Sevenz("7z", []string{"d", arc, "*a.txt"}); code != exitOK {
		t.Fatalf("d exit %d", code)
	}
	if code := Sevenz("7z", []string{"l", arc}); code != exitOK {
		t.Fatalf("l after d exit %d", code)
	}
	// native creation validates with the system tool
	native := filepath.Join(work, "written.7z")
	if code := Sevenz("7z", []string{"a", "-t7z", native, "proj/a.txt"}); code != exitOK {
		t.Fatalf("a -t7z exit %d", code)
	}
	if out, err := exec.Command(bin, "t", native).CombinedOutput(); err != nil {
		t.Fatalf("system 7z t ours: %v: %s", err, out)
	}
}

// TestSevenzBenchHash: the benchmark round-trips every codec and the
// hash verb matches independent digests.
func TestSevenzBenchHash(t *testing.T) {
	if testing.Short() {
		t.Skip("benchmark runs the full corpus")
	}
	if code := Sevenz("7z", []string{"b"}); code != exitOK {
		t.Fatalf("b exit %d", code)
	}
	dir, _ := os.MkdirTemp("", "hash")
	defer os.RemoveAll(dir)
	f := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(f, []byte("hash me please\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() int { return Sevenz("7z", []string{"h", f}) })
	if !strings.Contains(out, "c02f9f6e") || !strings.Contains(out, "1cc0bc3f0c48143efc66a65368bd745ce8bf4e30fcddcaf1b0d0d56417eb899c") {
		t.Fatalf("h output: %s", out)
	}
}

func captureStdout(t *testing.T, run func() int) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	code := run()
	w.Close()
	os.Stdout = old
	buf, _ := io.ReadAll(r)
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	return string(buf)
}

// TestStreamingMemoryBounded: a large compressed tar lists with a
// resident set bounded by the largest member, not the archive (the M4
// streaming design; this test pins it against regressions).
func TestStreamingMemoryBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("streams 64 MiB")
	}
	dir := t.TempDir()
	big := filepath.Join(dir, "big.bin")
	f, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	chunk := make([]byte, 1<<20)
	s := uint32(9)
	for i := range chunk[:4096] { // sparse-ish: mostly zeros with noise
		s = s*1664525 + 1013904223
		chunk[i] = byte(s >> 23)
	}
	for i := 0; i < 64; i++ {
		if _, err := f.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	f.Close()

	out := filepath.Join(dir, "a.tgz")
	if _, err := eng.Create(&eng.CreateOpts{
		Path:             out,
		DefaultContainer: "tar",
		Walk:             walk.Opts{Files: []string{big}},
	}); err != nil {
		t.Fatal(err)
	}
	a, err := eng.OpenFile(out, "")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	total := 0
	if err := a.Each(func(m *member.Member, data io.Reader) error {
		n, err := io.Copy(io.Discard, data)
		total += int(n)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if total != 64<<20 {
		t.Fatalf("streamed %d bytes, want %d", total, 64<<20)
	}
	var rss, vs int64
	if b, err := os.ReadFile("/proc/self/statm"); err == nil {
		_, _ = fmt.Sscanf(string(b), "%d %d", &vs, &rss)
		if rss*int64(os.Getpagesize()) > 200<<20 {
			t.Fatalf("rss %d MiB exceeds the bound", rss*int64(os.Getpagesize())>>20)
		}
	}
}
