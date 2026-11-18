/*
Copyright (C) Philip Schlump, 2012-2026.

MIT Licensed.
*/

package eng

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestSplitSetDetection covers the sibling-part discovery: what makes
// a set, what opens it, and what does not.
func TestSplitSetDetection(t *testing.T) {
	dir := t.TempDir()
	mk := func(n string) {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := splitSet(filepath.Join(dir, "a.zip")); ok {
		t.Fatal("a lone .zip is not a split set")
	}
	mk("a.zip")
	if _, ok := splitSet(filepath.Join(dir, "a.zip")); ok {
		t.Fatal("a .zip without parts is not a split set")
	}
	mk("a.z01")
	mk("a.z02")
	parts, ok := splitSet(filepath.Join(dir, "a.zip"))
	if !ok || len(parts) != 3 {
		t.Fatalf("parts %v ok=%v", parts, ok)
	}
	if filepath.Base(parts[0]) != "a.z01" || filepath.Base(parts[2]) != "a.zip" {
		t.Fatalf("order wrong: %v", parts)
	}
	if parts2, ok := splitSet(filepath.Join(dir, "a.z02")); !ok || len(parts2) != 3 {
		t.Fatalf("opening a part should open the set: %v %v", parts2, ok)
	}
	if err := os.Remove(filepath.Join(dir, "a.z01")); err != nil {
		t.Fatal(err)
	}
	if _, ok := splitSet(filepath.Join(dir, "a.zip")); ok {
		t.Fatal("a gap in the part sequence must not assemble")
	}
}

// TestSplitZipAssembly: a `zip -s` split set (numbered parts beside
// the .zip last part) opens and extracts as one archive from any
// member of the set.  The parts state offsets relative to themselves,
// so the recovery parse rebuilds them on the joined bytes — something
// unzip(1) itself cannot do without merging first.
func TestSplitZipAssembly(t *testing.T) {
	sysZip, err := exec.LookPath("zip")
	if err != nil {
		t.Skip("system zip not available")
	}
	src := t.TempDir()
	mk := func(rel string, data []byte) {
		full := filepath.Join(src, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	big := make([]byte, 300000) // big enough to span several 64 KiB parts
	s := uint32(7)
	for i := range big {
		s = s*1664525 + 1013904223
		big[i] = byte(s >> 23)
	}
	mk("proj/a.txt", []byte("alpha\n"))
	mk("proj/sub/b.txt", []byte("beta\n"))
	mk("proj/big.bin", big)

	work := t.TempDir()
	arc := filepath.Join(work, "whole.zip")
	cmd := exec.Command(sysZip, "-q", "-r", "-s", "64k", arc, "proj")
	cmd.Dir = src
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("zip -s: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(work, "whole.z01")); err != nil {
		t.Fatalf("no split parts were written: %v", err)
	}

	for _, open := range []string{"whole.zip", "whole.z01"} {
		a, err := OpenFile(filepath.Join(work, open), "")
		if err != nil {
			t.Fatalf("open %s: %v", open, err)
		}
		if a.Format != "zip" {
			t.Fatalf("%s: format %s", open, a.Format)
		}
		if len(a.Members) != 5 { // proj/, a.txt, big.bin, sub/, b.txt
			t.Fatalf("%s: members %d: %v", open, len(a.Members), a.Members)
		}
		var assembled, rebuilt bool
		for _, n := range a.Notes {
			if strings.Contains(n, "split zip: assembled") {
				assembled = true
			}
			if strings.Contains(n, "rebuilt") {
				rebuilt = true
			}
		}
		if !assembled || !rebuilt {
			t.Fatalf("%s: notes %v", open, a.Notes)
		}

		dst := filepath.Join(t.TempDir(), "out")
		if err := Extract(a, &ExtractOpts{Dest: dst, Warn: func(string) {}}); err != nil {
			t.Fatalf("%s: extract: %v", open, err)
		}
		for rel, want := range map[string][]byte{
			"proj/a.txt":     []byte("alpha\n"),
			"proj/sub/b.txt": []byte("beta\n"),
			"proj/big.bin":   big,
		} {
			got, err := os.ReadFile(filepath.Join(dst, rel))
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("%s: %s content mismatch (len %d, err %v)", open, rel, len(got), err)
			}
		}
	}

	// Sniffing any part reports the assembled archive.
	info, err := SniffFile(arc)
	if err != nil {
		t.Fatal(err)
	}
	if info.Format != "zip" || info.Members != 5 {
		t.Fatalf("sniff: %+v", info)
	}
}
