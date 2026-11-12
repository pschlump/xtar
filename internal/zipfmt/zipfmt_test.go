/*
Copyright (C) Philip Schlump, 2012-2026.

BSD 3 Clause Licensed.
*/

package zipfmt

import (
	"archive/zip"
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/pschlump/xtar/internal/member"
)

func mt() time.Time { return time.Date(2026, 6, 15, 14, 30, 20, 0, time.Local) }

func sampleMembers() []member.Member {
	return []member.Member{
		{Name: "d/", Kind: member.Directory, Mode: 0o755, ModTime: mt()},
		{Name: "d/a.txt", Kind: member.Regular, Mode: 0o644, Data: []byte("alpha alpha alpha alpha alpha\n"), ModTime: mt(), Method: MethodDeflate},
		{Name: "d/zeros", Kind: member.Regular, Mode: 0o600, Data: bytes.Repeat([]byte{0}, 100), ModTime: mt()}, // no method: store
		{Name: "d/link", Kind: member.SymLink, Mode: 0o777, LinkName: "a.txt", ModTime: mt(), Method: MethodDeflate},
	}
}

// TestStdlibReadsOurZip: the standard library must read what we write
// — deflate and store methods, the directory marker, and the archive
// comment.
func TestStdlibReadsOurZip(t *testing.T) {
	blob, err := Build(sampleMembers(), "a comment", "")
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(blob), int64(len(blob)))
	if err != nil {
		t.Fatal(err)
	}
	if zr.Comment != "a comment" {
		t.Fatalf("comment %q", zr.Comment)
	}
	seen := map[string]int{}
	for _, f := range zr.File {
		seen[f.Name]++
		switch f.Name {
		case "d/a.txt":
			if f.FileHeader.Method != zip.Deflate {
				t.Fatalf("a.txt method %d, want deflate", f.FileHeader.Method)
			}
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(rc)
			rc.Close()
			if err != nil || string(data) != "alpha alpha alpha alpha alpha\n" {
				t.Fatalf("a.txt content %q %v", data, err)
			}
		case "d/zeros":
			// 100 zero bytes deflate well; either method is fine as
			// long as the content survives.
			rc, _ := f.Open()
			data, _ := io.ReadAll(rc)
			rc.Close()
			if len(data) != 100 {
				t.Fatalf("zeros content %d bytes", len(data))
			}
		case "d/":
			if !f.FileInfo().IsDir() {
				t.Fatal("d/ not a directory for stdlib")
			}
		}
	}
	for _, want := range []string{"d/", "d/a.txt", "d/zeros", "d/link"} {
		if seen[want] == 0 {
			t.Fatalf("stdlib did not see %s", want)
		}
	}
}

// TestOurParseOfOurBuild: round trip through our own parser, checking
// kinds, modes, data, symlink targets, and per-entry raw state.
func TestOurParseOfOurBuild(t *testing.T) {
	blob, err := Build(sampleMembers(), "", "")
	if err != nil {
		t.Fatal(err)
	}
	a, err := Parse(blob, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Members) != 4 {
		t.Fatalf("members %d", len(a.Members))
	}
	dir, txt, zeros, link := a.Members[0], a.Members[1], a.Members[2], a.Members[3]
	if dir.Kind != member.Directory || dir.Name != "d" {
		t.Fatalf("dir member %+v", dir)
	}
	if txt.Kind != member.Regular || string(txt.Data) != "alpha alpha alpha alpha alpha\n" || txt.Mode != 0o644 {
		t.Fatalf("txt member %+v", txt)
	}
	if txt.ModTime.Unix() != mt().Unix() {
		t.Fatalf("mtime %v (DOS rounds to even seconds)", txt.ModTime)
	}
	if len(zeros.Data) != 100 {
		t.Fatalf("zeros %d bytes", len(zeros.Data))
	}
	if link.Kind != member.SymLink || link.LinkName != "a.txt" {
		t.Fatalf("link member %+v", link)
	}
	for _, m := range a.Members {
		if m.Raw == nil {
			t.Fatalf("%s has no raw state", m.Name)
		}
	}
}

// TestStdlibWriteWeRead: the standard library writes (deflate and
// store, with a comment); we must read it back.
func TestStdlibWriteWeRead(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("hello zip\n"))
	w, err = zw.CreateHeader(&zip.FileHeader{Name: "stored.bin", Method: zip.Store, Modified: mt()})
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("\x00\x01\x02stored"))
	if err := zw.SetComment("from stdlib"); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	a, err := Parse(buf.Bytes(), "")
	if err != nil {
		t.Fatal(err)
	}
	if a.Comment != "from stdlib" {
		t.Fatalf("comment %q", a.Comment)
	}
	if len(a.Members) != 2 {
		t.Fatalf("members %d", len(a.Members))
	}
	if string(a.Members[0].Data) != "hello zip\n" {
		t.Fatalf("hello %q", a.Members[0].Data)
	}
	if string(a.Members[1].Data) != "\x00\x01\x02stored" {
		t.Fatalf("stored %q", a.Members[1].Data)
	}
	if a.Members[1].Raw.Method != MethodStore {
		t.Fatalf("stored method %d", a.Members[1].Raw.Method)
	}
}

// TestEncryptionRoundTrip: ZipCrypto entries decrypt with the right
// password and are rejected with the wrong one.
func TestEncryptionRoundTrip(t *testing.T) {
	mems := []member.Member{
		{Name: "enc.txt", Kind: member.Regular, Mode: 0o644, Data: []byte("secret content\n"), ModTime: mt(), Encrypted: true},
		{Name: "plain.txt", Kind: member.Regular, Mode: 0o644, Data: []byte("open content\n"), ModTime: mt()},
	}
	blob, err := Build(mems, "", "pw123")
	if err != nil {
		t.Fatal(err)
	}
	a, err := Parse(blob, "pw123")
	if err != nil {
		t.Fatal(err)
	}
	if string(a.Members[0].Data) != "secret content\n" {
		t.Fatalf("decrypted %q", a.Members[0].Data)
	}
	if _, err := Parse(blob, "wrong"); err == nil {
		t.Fatal("wrong password accepted")
	}
	if _, err := Parse(blob, ""); err == nil {
		t.Fatal("missing password accepted")
	}
	// stdlib flags the entry as encrypted
	zr, err := zip.NewReader(bytes.NewReader(blob), int64(len(blob)))
	if err != nil {
		t.Fatal(err)
	}
	if zr.File[0].Flags&1 == 0 {
		t.Fatal("entry not marked encrypted")
	}
}

// TestLosslessRebuild: parsing then rebuilding with KeepStored must
// produce byte-identical output (no password needed even for the
// encrypted entry).
func TestLosslessRebuild(t *testing.T) {
	blob, err := Build(sampleMembers(), "keep me", "")
	if err != nil {
		t.Fatal(err)
	}
	a, err := Parse(blob, "")
	if err != nil {
		t.Fatal(err)
	}
	for i := range a.Members {
		a.Members[i].KeepStored = true
	}
	again, err := Build(a.Members, a.Comment, "")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(blob, again) {
		t.Fatal("KeepStored rebuild is not byte-identical")
	}
}

// TestBZip2Method: method 12 round trips through our parser (the
// stdlib cannot read bzip2 zips, so this is our own loop).
func TestBZip2Method(t *testing.T) {
	mems := []member.Member{
		{Name: "bz.bin", Kind: member.Regular, Mode: 0o644,
			Data: bytes.Repeat([]byte("bzip2 bzip2 bzip2 "), 20), ModTime: mt(), Method: MethodBZip2},
	}
	blob, err := Build(mems, "", "")
	if err != nil {
		t.Fatal(err)
	}
	a, err := Parse(blob, "")
	if err != nil {
		t.Fatal(err)
	}
	if a.Members[0].Raw.Method != MethodBZip2 {
		t.Fatalf("method %d", a.Members[0].Raw.Method)
	}
	if !bytes.Equal(a.Members[0].Data, mems[0].Data) {
		t.Fatal("bzip2 content mangled")
	}
}

// TestPrependedData: junk before the zip (SFX stub) is detected via
// the shift and the archive still parses.
func TestPrependedData(t *testing.T) {
	blob, err := Build(sampleMembers(), "", "")
	if err != nil {
		t.Fatal(err)
	}
	sfx := append([]byte("THIS IS A FAKE EXECUTABLE STUB\x00\x01\x02"), blob...)
	a, err := Parse(sfx, "")
	if err != nil {
		t.Fatal(err)
	}
	if a.Shift != int64(len(sfx)-len(blob)) {
		t.Fatalf("shift %d, want %d", a.Shift, len(sfx)-len(blob))
	}
	if len(a.Members) != 4 {
		t.Fatalf("members %d", len(a.Members))
	}
}

// TestUTF8Names: non-ASCII names set the EFS flag and survive.
func TestUTF8Names(t *testing.T) {
	mems := []member.Member{
		{Name: "ünïcode/файл.txt", Kind: member.Regular, Mode: 0o644, Data: []byte("x"), ModTime: mt()},
	}
	blob, err := Build(mems, "", "")
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(blob), int64(len(blob)))
	if err != nil {
		t.Fatal(err)
	}
	if zr.File[0].Name != "ünïcode/файл.txt" {
		t.Fatalf("stdlib saw %q", zr.File[0].Name)
	}
	if zr.File[0].Flags&0x800 == 0 {
		t.Fatal("EFS flag not set")
	}
	a, err := Parse(blob, "")
	if err != nil || a.Members[0].Name != "ünïcode/файл.txt" {
		t.Fatalf("our parse: %v %+v", err, a.Members)
	}
}

// TestEmptyArchive: an EOCD with zero entries parses.
func TestEmptyArchive(t *testing.T) {
	blob, err := Build(nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	a, err := Parse(blob, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Members) != 0 {
		t.Fatalf("members %d", len(a.Members))
	}
}
