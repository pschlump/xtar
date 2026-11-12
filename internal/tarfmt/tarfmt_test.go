/*
Copyright (C) Philip Schlump, 2012-2026.

BSD 3 Clause Licensed.
*/

package tarfmt_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pschlump/xtar/internal/member"
	"github.com/pschlump/xtar/internal/tarfmt"
)

var base = time.Unix(1731400000, 0)

func fixture() []member.Member {
	return []member.Member{
		{Name: "dir", Kind: member.Directory, Mode: 0o755, ModTime: base, UID: 1000, GID: 20, Uname: "philip", Gname: "staff"},
		{Name: "dir/file.txt", Kind: member.Regular, Mode: 0o644, ModTime: base, Data: []byte("hello world\n"), Size: 12, UID: 1000, GID: 20},
		{Name: "dir/exec.sh", Kind: member.Regular, Mode: 0o755, ModTime: base, Data: []byte("#!/bin/sh\n"), Size: 10, UID: 1000, GID: 20},
		{Name: "dir/setuid", Kind: member.Regular, Mode: 0o4755, ModTime: base, Data: []byte("x"), Size: 1, UID: 0, GID: 0},
		{Name: "dir/link", Kind: member.SymLink, Mode: 0o777, LinkName: "file.txt", Data: []byte("file.txt"), ModTime: base},
		{Name: "dir/hard", Kind: member.HardLink, LinkName: "dir/file.txt", ModTime: base},
		{Name: "pipe", Kind: member.FIFO, Mode: 0o644, ModTime: base},
		{Name: "odd-name-Ünïcødé-日本語.txt", Kind: member.Regular, Mode: 0o644, ModTime: base, Data: []byte("unicode"), Size: 7, UID: 1000, GID: 20},
	}
}

func TestRoundTrip(t *testing.T) {
	for _, format := range []string{"gnu", "ustar", "pax", "v7"} {
		mems := fixture()
		blob, err := tarfmt.Build(format, mems)
		if err != nil {
			t.Fatalf("format %s: build: %v", format, err)
		}
		got, err := tarfmt.Parse(blob)
		if err != nil {
			t.Fatalf("format %s: parse: %v", format, err)
		}
		if len(got.Members) != len(mems) {
			t.Fatalf("format %s: got %d members, want %d", format, len(got.Members), len(mems))
		}
		for i, m := range mems {
			g := got.Members[i]
			if g.Name != m.Name {
				t.Errorf("format %s member %d: name %q, want %q", format, i, g.Name, m.Name)
			}
			if g.Kind != m.Kind {
				t.Errorf("format %s member %q: kind %v, want %v", format, m.Name, g.Kind, m.Kind)
			}
			if g.Mode != m.Mode {
				t.Errorf("format %s member %q: mode %o, want %o", format, m.Name, g.Mode, m.Mode)
			}
			if g.LinkName != m.LinkName {
				t.Errorf("format %s member %q: link %q, want %q", format, m.Name, g.LinkName, m.LinkName)
			}
			if m.Kind == member.Regular && !bytes.Equal(g.Data, m.Data) {
				t.Errorf("format %s member %q: data mismatch", format, m.Name)
			}
			if g.ModTime.Unix() != m.ModTime.Unix() {
				t.Errorf("format %s member %q: mtime %v, want %v", format, m.Name, g.ModTime, m.ModTime)
			}
		}
	}
}

func TestLongNames(t *testing.T) {
	long := strings.Repeat("deep/", 30) + "leaf.txt" // 155 bytes
	link := strings.Repeat("up/", 40) + "target"     // 120 bytes
	mems := []member.Member{
		{Name: long, Kind: member.Regular, Mode: 0o644, Data: []byte("far"), Size: 3, ModTime: base},
		{Name: "lnk", Kind: member.SymLink, LinkName: link, Data: []byte(link), ModTime: base},
	}
	// ustar cannot store link names longer than 100 bytes (no prefix
	// mechanism for links); that error is part of the contract.
	for _, format := range []string{"gnu", "pax"} {
		blob, err := tarfmt.Build(format, mems)
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		got, err := tarfmt.Parse(blob)
		if err != nil {
			t.Fatalf("%s: parse: %v", format, err)
		}
		if len(got.Members) != 2 {
			t.Fatalf("%s: got %d members", format, len(got.Members))
		}
		if got.Members[0].Name != long {
			t.Errorf("%s: long name = %q", format, got.Members[0].Name)
		}
		if got.Members[1].LinkName != link {
			t.Errorf("%s: long link = %q", format, got.Members[1].LinkName)
		}
	}
}

func TestBase256Numbers(t *testing.T) {
	mems := []member.Member{{
		Name: "biguid", Kind: member.Regular, Mode: 0o644,
		UID: 1 << 28, GID: 1 << 29, Data: []byte("x"), Size: 1, ModTime: time.Unix(1<<34, 0),
	}}
	blob, err := tarfmt.Build("gnu", mems)
	if err != nil {
		t.Fatal(err)
	}
	got, err := tarfmt.Parse(blob)
	if err != nil {
		t.Fatal(err)
	}
	m := got.Members[0]
	if m.UID != 1<<28 || m.GID != 1<<29 {
		t.Errorf("uid/gid = %d/%d, want %d/%d", m.UID, m.GID, 1<<28, 1<<29)
	}
	if m.ModTime.Unix() != 1<<34 {
		t.Errorf("mtime = %v", m.ModTime)
	}
}

func TestUstarPrefixSplit(t *testing.T) {
	name := strings.Repeat("a", 60) + "/" + strings.Repeat("b", 60) // 121 bytes
	mems := []member.Member{{Name: name, Kind: member.Regular, Mode: 0o644, Data: []byte("z"), Size: 1, ModTime: base}}
	blob, err := tarfmt.Build("ustar", mems)
	if err != nil {
		t.Fatal(err)
	}
	got, err := tarfmt.Parse(blob)
	if err != nil {
		t.Fatal(err)
	}
	if got.Members[0].Name != name {
		t.Errorf("name = %q, want %q", got.Members[0].Name, name)
	}
}

func TestEmptyArchive(t *testing.T) {
	blob, err := tarfmt.Build("gnu", nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := tarfmt.Parse(blob)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Members) != 0 {
		t.Errorf("members = %d", len(got.Members))
	}
}

func TestTruncatedIsError(t *testing.T) {
	mems := []member.Member{{
		Name: "big.bin", Kind: member.Regular, Mode: 0o644,
		Data: bytes.Repeat([]byte{0xAB}, 10000), Size: 10000, ModTime: base,
	}}
	blob, err := tarfmt.Build("gnu", mems)
	if err != nil {
		t.Fatal(err)
	}
	// Cut inside the member's data: header parsed, content missing.
	if _, err := tarfmt.Parse(blob[:512+5000]); err == nil {
		t.Error("truncated archive parsed without error")
	}
}

func TestSystemTarInterop(t *testing.T) {
	exe, err := exec.LookPath("tar")
	if err != nil {
		t.Skip("system tar not installed")
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "src", "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "src", "a.txt"), []byte("alpha"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "src", "sub", "b.bin"), []byte("\x00\x01\x02bin"), 0o644); err != nil {
		t.Fatal(err)
	}

	// system tar creates, xtar parses
	sysTar := filepath.Join(dir, "sys.tar")
	if out, err := exec.Command(exe, "-cf", sysTar, "-C", dir, "src").CombinedOutput(); err != nil {
		t.Fatalf("system tar: %v: %s", err, out)
	}
	data, err := os.ReadFile(sysTar)
	if err != nil {
		t.Fatal(err)
	}
	a, err := tarfmt.Parse(data)
	if err != nil {
		t.Fatalf("parse system tar: %v", err)
	}
	names := map[string]bool{}
	for _, m := range a.Members {
		names[m.Name] = true
	}
	for _, want := range []string{"src", "src/a.txt", "src/sub", "src/sub/b.bin"} {
		if !names[want] {
			t.Errorf("member %q missing from parse of system tar (have %v)", want, names)
		}
	}
	if d, ok := names["src/a.txt"]; !ok || d {
		_ = d
	}
	var alpha *member.Member
	for i := range a.Members {
		if a.Members[i].Name == "src/a.txt" {
			alpha = &a.Members[i]
		}
	}
	if alpha == nil || !bytes.Equal(alpha.Data, []byte("alpha")) {
		t.Errorf("src/a.txt content mismatch: %v", alpha)
	}

	// xtar creates (each format), system tar lists and extracts
	for _, format := range []string{"gnu", "ustar", "pax"} {
		mems := []member.Member{
			{Name: "x", Kind: member.Directory, Mode: 0o755, ModTime: base},
			{Name: "x/y.txt", Kind: member.Regular, Mode: 0o644, ModTime: base, Data: []byte("zeta"), Size: 4},
			{Name: "x/ünïcode", Kind: member.Regular, Mode: 0o644, ModTime: base, Data: []byte("ü"), Size: 2},
		}
		blob, err := tarfmt.Build(format, mems)
		if err != nil {
			t.Fatalf("%s build: %v", format, err)
		}
		ourTar := filepath.Join(dir, "our-"+format+".tar")
		if err := os.WriteFile(ourTar, blob, 0o644); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(exe, "-tf", ourTar).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: system tar -tf: %v: %s", format, err, out)
		}
		for _, want := range []string{"x/", "x/y.txt"} {
			if !strings.Contains(string(out), want) {
				t.Errorf("%s: system tar listing missing %q: %s", format, want, out)
			}
		}
		exDir := filepath.Join(dir, "ex-"+format)
		if err := os.MkdirAll(exDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(exe, "-xf", ourTar, "-C", exDir).CombinedOutput(); err != nil {
			t.Fatalf("%s: system tar -xf: %v: %s", format, err, out)
		}
		got, err := os.ReadFile(filepath.Join(exDir, "x", "y.txt"))
		if err != nil || !bytes.Equal(got, []byte("zeta")) {
			t.Errorf("%s: extracted content mismatch: %q %v", format, got, err)
		}
	}
}
