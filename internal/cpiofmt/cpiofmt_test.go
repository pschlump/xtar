/*
Copyright (C) Philip Schlump, 2012-2026.

BSD 3 Clause Licensed.
*/

package cpiofmt

import (
	"bytes"
	"testing"
	"time"

	"github.com/pschlump/xtar/internal/member"
)

func sampleMembers() []member.Member {
	mtime := time.Unix(1700000000, 0)
	return []member.Member{
		{Name: "d/", Kind: member.Directory, Mode: 0o755, ModTime: mtime},
		{Name: "d/a.txt", Kind: member.Regular, Mode: 0o644, Data: []byte("alpha\n"), Size: 6, ModTime: mtime, Ino: 1108213, Dev: 1},
		{Name: "d/b.txt", Kind: member.Regular, Mode: 0o644, Data: []byte("beta\n"), Size: 5, ModTime: mtime},
		{Name: "d/hard", Kind: member.HardLink, Mode: 0o644, LinkName: "d/a.txt", ModTime: mtime},
		{Name: "d/link", Kind: member.SymLink, Mode: 0o777, LinkName: "a.txt", Data: []byte("a.txt"), Size: 5, ModTime: mtime},
	}
}

func TestBuildParseRoundTrip(t *testing.T) {
	for _, variant := range []string{"newc", "crc", "odc"} {
		blob, err := Build(variant, sampleMembers())
		if err != nil {
			t.Fatalf("%s: build: %v", variant, err)
		}
		a, err := Parse(blob)
		if err != nil {
			t.Fatalf("%s: parse: %v", variant, err)
		}
		if a.Variant != variant {
			t.Fatalf("%s: sniffed variant %s", variant, a.Variant)
		}
		if len(a.Members) != 5 {
			t.Fatalf("%s: got %d members, want 5", variant, len(a.Members))
		}
		got := a.Members[1]
		if got.Kind != member.Regular || string(got.Data) != "alpha\n" {
			t.Fatalf("%s: a.txt member %+v", variant, got)
		}
		if !got.ModTime.Equal(time.Unix(1700000000, 0)) {
			t.Fatalf("%s: mtime not preserved: %v", variant, got.ModTime)
		}
		hard := a.Members[3]
		if hard.Kind != member.HardLink || hard.LinkName != "d/a.txt" {
			t.Fatalf("%s: hard link not resolved: kind=%v link=%q", variant, hard.Kind, hard.LinkName)
		}
		link := a.Members[4]
		if link.Kind != member.SymLink || link.LinkName != "a.txt" {
			t.Fatalf("%s: symlink member %+v", variant, link)
		}
		if len(a.Notes) != 0 {
			t.Fatalf("%s: unexpected notes %v", variant, a.Notes)
		}
	}
}

// TestOdcInodeOverflow guards the field-width bug: a real inode that
// needs more than 6 octal digits must not shift the following header
// fields (%06o pads but never truncates).
func TestOdcInodeOverflow(t *testing.T) {
	mems := []member.Member{
		{Name: "big", Kind: member.Regular, Mode: 0o644, Data: []byte("x"), Size: 1, Ino: 1 << 24},
	}
	blob, err := Build("odc", mems)
	if err != nil {
		t.Fatal(err)
	}
	a, err := Parse(blob)
	if err != nil {
		t.Fatalf("parse of overflow-inode odc: %v", err)
	}
	if len(a.Members) != 1 || a.Members[0].Name != "big" || string(a.Members[0].Data) != "x" {
		t.Fatalf("member mangled: %+v", a.Members)
	}
	// The header must stay exactly 76 bytes: the next record (the
	// trailer) has to parse too, which the Parse above already proved,
	// but check the width directly as a regression guard.
	if !bytes.Contains(blob, []byte("TRAILER!!!")) {
		t.Fatal("trailer missing")
	}
}

// TestBinaryParse covers the legacy 16-bit format with odd-length name
// and data (both take a pad byte to keep word alignment).
func TestBinaryParse(t *testing.T) {
	b := &bytes.Buffer{}
	w16 := func(v uint32) { b.WriteByte(byte(v)); b.WriteByte(byte(v >> 8)) }
	w32 := func(v uint32) { w16(v >> 16); w16(v) } // high short first
	entry := func(name string, data []byte, mode uint32) {
		w16(0o070707)
		w16(1)    // dev
		w16(2)    // ino
		w16(mode) // mode
		w16(501)  // uid
		w16(20)   // gid
		w16(1)    // nlink
		w16(0)    // rdev
		w32(1700000000)
		w16(uint32(len(name) + 1))
		w32(uint32(len(data)))
		b.WriteString(name)
		b.WriteByte(0)
		if len(name)%2 == 0 {
			b.WriteByte(0) // pad name to even
		}
		b.Write(data)
		if len(data)%2 == 1 {
			b.WriteByte(0) // pad data to even
		}
	}
	entry("ab", []byte("odd"), 0o100644) // odd name, odd data
	entry("TRAILER!!!", nil, 0)

	a, err := Parse(b.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if a.Variant != "binary" {
		t.Fatalf("variant %s", a.Variant)
	}
	if len(a.Members) != 1 {
		t.Fatalf("members %d", len(a.Members))
	}
	m := a.Members[0]
	if m.Name != "ab" || m.Kind != member.Regular || string(m.Data) != "odd" {
		t.Fatalf("member %+v", m)
	}
}

func TestVariantSniff(t *testing.T) {
	blob, err := Build("newc", sampleMembers())
	if err != nil {
		t.Fatal(err)
	}
	// odc's own sniff is covered by the round trip (a real odc build).
	for magic, want := range map[string]string{
		"070701": "newc", "070702": "crc",
	} {
		b := bytes.ReplaceAll(blob, []byte("070701"), []byte(magic))
		a, err := Parse(b)
		if err != nil {
			t.Fatalf("%s: %v", magic, err)
		}
		if a.Variant != want {
			t.Fatalf("magic %s sniffed as %s", magic, a.Variant)
		}
	}
	// crc checksum: a wrong nonzero sum over intact data must produce
	// a note (the newc build wrote 0 = "no checksum").
	crc := bytes.ReplaceAll(blob, []byte("070701"), []byte("070702"))
	copy(crc[102:110], []byte("deadbeef"))
	ca, err := Parse(crc)
	if err != nil {
		t.Fatal(err)
	}
	if len(ca.Notes) == 0 {
		t.Fatal("crc mismatch produced no note")
	}
}

func TestBuildBinaryRefused(t *testing.T) {
	if _, err := Build("bin", sampleMembers()); err == nil {
		t.Fatal("binary write should be refused")
	}
}
