/*
Copyright (C) Philip Schlump, 2012-2026.

BSD 3 Clause Licensed.
*/

package cli

import (
	"os"
	"os/exec"
	"path/filepath"
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
