/*
Copyright (C) Philip Schlump, 2012-2026.

MIT Licensed.
*/

package arfmt

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// arHeader builds one 60-byte member header.
func arHeader(name string, size int) []byte {
	h := make([]byte, 60)
	copy(h, []byte(name))
	put := func(off, width int, v string) {
		copy(h[off:off+width], []byte(v))
	}
	put(16, 12, "1700000000 ")
	put(40, 8, "100644  ")
	put(48, 10, strings.Repeat(" ", 10))
	copy(h[48:], []byte(pad(size, 10)))
	copy(h[58:], "`\n")
	return h
}

func pad(v, w int) string {
	s := []byte(strings.Repeat(" ", w))
	n := []byte(itoa(v))
	copy(s[w-len(n):], n)
	return string(s)
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var b []byte
	for v > 0 {
		b = append([]byte{byte('0' + v%10)}, b...)
		v /= 10
	}
	return string(b)
}

func TestParsePlain(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString(magic)
	buf.Write(arHeader("hello.txt", 5))
	buf.WriteString("world")
	buf.WriteByte('\n') // alignment pad
	buf.Write(arHeader("short", 4))
	buf.WriteString("abcd") // even size: no alignment pad
	a, err := Parse(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Members) != 2 {
		t.Fatalf("members %d", len(a.Members))
	}
	if a.Members[0].Name != "hello.txt" || string(a.Members[0].Data) != "world" {
		t.Fatalf("member 0: %+v", a.Members[0])
	}
	if a.Members[1].Name != "short" || string(a.Members[1].Data) != "abcd" {
		t.Fatalf("member 1: %+v", a.Members[1])
	}
	if a.Members[0].Mode != 0o644 {
		t.Fatalf("mode %o", a.Members[0].Mode)
	}
}

func TestParseBSDNames(t *testing.T) {
	// #1/len: the name rides in the payload; the size counts it
	name := []byte("a-long-member-name.bin")
	payload := []byte("payload bytes")
	var buf bytes.Buffer
	buf.WriteString(magic)
	buf.Write(arHeader("#1/"+itoa(len(name)), len(name)+len(payload)))
	buf.Write(name)
	buf.Write(payload)
	if (len(name)+len(payload))%2 == 1 {
		buf.WriteByte('\n')
	}
	a, err := Parse(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Members) != 1 || a.Members[0].Name != "a-long-member-name.bin" {
		t.Fatalf("members: %+v", a.Members)
	}
	if string(a.Members[0].Data) != "payload bytes" {
		t.Fatalf("data: %q", a.Members[0].Data)
	}
}

func TestParseGNULongNames(t *testing.T) {
	table := "really-long-name-that-does-not-fit/\neven-longer-second-name/\n"
	var buf bytes.Buffer
	buf.WriteString(magic)
	// the // string table is a member itself
	buf.Write(arHeader("//", len(table)))
	buf.WriteString(table)
	if len(table)%2 == 1 {
		buf.WriteByte('\n')
	}
	buf.Write(arHeader("/0", 3))
	buf.WriteString("one")
	buf.WriteByte('\n')
	buf.Write(arHeader("/36", 3))
	buf.WriteString("two")
	buf.WriteByte('\n')
	a, err := Parse(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Members) != 2 {
		t.Fatalf("members %d: %+v", len(a.Members), a.Members)
	}
	if a.Members[0].Name != "really-long-name-that-does-not-fit" || a.Members[1].Name != "even-longer-second-name" {
		t.Fatalf("GNU names: %q %q", a.Members[0].Name, a.Members[1].Name)
	}
}

func TestParseSkipsSymbolTables(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString(magic)
	buf.Write(arHeader("/", 8))
	buf.WriteString("SYMTAB!!")
	buf.Write(arHeader("__.SYMDEF SORTED", 4))
	buf.WriteString("junk")
	buf.Write(arHeader("real.o", 4))
	buf.WriteString("abcd")
	a, err := Parse(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Members) != 1 || a.Members[0].Name != "real.o" {
		t.Fatalf("members: %+v", a.Members)
	}
}

// TestSystemAr parses a compiler-made static library when ar exists.
func TestSystemAr(t *testing.T) {
	bin, err := exec.LookPath("ar")
	if err != nil {
		t.Skip("ar not installed")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "f.c")
	if err := os.WriteFile(src, []byte("int f(void){return 1;}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cc", "-c", src, "-o", filepath.Join(dir, "f.o")).CombinedOutput(); err != nil {
		t.Skipf("cc unavailable: %v: %s", err, out)
	}
	lib := filepath.Join(dir, "libtest.a")
	if out, err := exec.Command(bin, "rcs", lib, filepath.Join(dir, "f.o")).CombinedOutput(); err != nil {
		t.Fatalf("ar rcs: %v\n%s", err, out)
	}
	b, err := os.ReadFile(lib)
	if err != nil {
		t.Fatal(err)
	}
	a, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Members) != 1 || a.Members[0].Name != "f.o" {
		t.Fatalf("members: %+v", a.Members)
	}
	if len(a.Members[0].Data) == 0 {
		t.Fatal("f.o has no data")
	}
}

func TestMalformed(t *testing.T) {
	if _, err := Parse(nil); err == nil {
		t.Error("empty parsed")
	}
	if _, err := Parse([]byte("not an ar")); err == nil {
		t.Error("bad magic parsed")
	}
	// truncated payload
	var buf bytes.Buffer
	buf.WriteString(magic)
	buf.Write(arHeader("big", 100))
	buf.WriteString("short")
	if _, err := Parse(buf.Bytes()); err == nil {
		t.Error("truncated member parsed")
	}
	// bad header terminator
	buf.Reset()
	buf.WriteString(magic)
	h := arHeader("x", 1)
	h[58] = 'z'
	buf.Write(h)
	buf.WriteString("a\n")
	if _, err := Parse(buf.Bytes()); err == nil {
		t.Error("bad terminator parsed")
	}
}
