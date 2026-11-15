/*
Copyright (C) Philip Schlump, 2012-2026.

BSD 3 Clause Licensed.
*/

package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestSystemZstdInterop checks our .tar.zst against the system tools
// both directions: bsdtar/gtar/zstd(1) read ours, and we read a frame
// from libarchive's encoder (whose FSE-Huffman-weights path differs
// from what the zstd CLI writes).
func TestSystemZstdInterop(t *testing.T) {
	if _, err := exec.LookPath("zstd"); err != nil {
		t.Skip("zstd not installed")
	}
	src, work := cliTree(t)
	t.Chdir(src)

	ours := filepath.Join(work, "ours.tar.zst")
	if code := Tar("tar", []string{"--zstd", "-cf", ours, "proj"}); code != exitOK {
		t.Fatalf("create exit %d", code)
	}
	if out, err := exec.Command("zstd", "-q", "-t", ours).CombinedOutput(); err != nil {
		t.Fatalf("zstd -t cannot test ours: %v\n%s", err, out)
	}
	if bsdtar, err := exec.LookPath("bsdtar"); err == nil {
		out, err := exec.Command(bsdtar, "--zstd", "-tf", ours).CombinedOutput()
		if err != nil || !strings.Contains(string(out), "proj/a.txt") {
			t.Fatalf("bsdtar cannot list ours: %v\n%s", err, out)
		}
		foreign := filepath.Join(work, "foreign.tar.zst")
		if out, err := exec.Command(bsdtar, "--zstd", "-cf", foreign, "proj").CombinedOutput(); err != nil {
			t.Fatalf("bsdtar create: %v\n%s", err, out)
		}
		a := openArchive(t, foreign)
		if a.Format != "tar" || len(a.Layers) != 1 || a.Layers[0] != "zstd" {
			t.Fatalf("foreign decode: %s %v", a.Format, a.Layers)
		}
		if len(a.Members) < 6 {
			t.Fatalf("foreign members %d", len(a.Members))
		}
		found := false
		for _, m := range a.Members {
			if m.Name == "proj/a.txt" {
				found = true
			}
		}
		if !found {
			t.Fatal("foreign archive missing proj/a.txt")
		}
	}
	// a .zst of a plain file resolves through the bare path too
	note := filepath.Join(work, "note.txt")
	if err := os.WriteFile(note, []byte("plain\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bare := filepath.Join(work, "note.txt.zst")
	if out, err := exec.Command("zstd", "-q", "-T1", "-c", note).Output(); err != nil {
		t.Fatalf("zstd encode: %v\n%s", err, out)
	} else if err := os.WriteFile(bare, out, 0o644); err != nil {
		t.Fatal(err)
	}
	a := openArchive(t, bare)
	if a.Format != "bare" || len(a.Members) != 1 || string(a.Members[0].Data) != "plain\n" {
		t.Fatalf("bare .zst decode: %s %+v", a.Format, a.Members)
	}
}
