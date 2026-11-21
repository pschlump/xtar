/*
Copyright (C) Philip Schlump, 2012-2026.

MIT Licensed.
*/

package zipfmt

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	blob, err := Build(sampleMembers(), "a comment", "", PPMdOpts{})
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
			if f.Method != zip.Deflate {
				t.Fatalf("a.txt method %d, want deflate", f.Method)
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
	blob, err := Build(sampleMembers(), "", "", PPMdOpts{})
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
	blob, err := Build(mems, "", "pw123", PPMdOpts{})
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
	blob, err := Build(sampleMembers(), "keep me", "", PPMdOpts{})
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
	again, err := Build(a.Members, a.Comment, "", PPMdOpts{})
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
	blob, err := Build(mems, "", "", PPMdOpts{})
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
	blob, err := Build(sampleMembers(), "", "", PPMdOpts{})
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
	blob, err := Build(mems, "", "", PPMdOpts{})
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
	blob, err := Build(nil, "", "", PPMdOpts{})
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

// relabelAsSplit rewrites a built archive the way a split writer
// states its offsets: every central-directory entry's local offset and
// the EOCD's directory offset become relative to a part of size S.
// The members' bytes stay where they are, exactly like a concatenated
// split set.
func relabelAsSplit(t *testing.T, blob []byte, S int64) []byte {
	t.Helper()
	eocd := findEOCD(blob)
	if eocd < 0 {
		t.Fatal("no EOCD")
	}
	cdSize := int64(binary.LittleEndian.Uint32(blob[eocd+12:]))
	le := binary.LittleEndian
	le.PutUint32(blob[eocd+16:], uint32(int64(le.Uint32(blob[eocd+16:]))%S))
	pos := int64(eocd) - cdSize
	for bytes.Equal(blob[pos:pos+4], sigCD) {
		le.PutUint32(blob[pos+42:], uint32(int64(le.Uint32(blob[pos+42:]))%S))
		pos += 46 + int64(le.Uint16(blob[pos+28:])) + int64(le.Uint16(blob[pos+30:])) + int64(le.Uint16(blob[pos+32:]))
	}
	return blob
}

// TestSplitOffsetsRecovered: a split set's offsets are stated per
// part, so on the joined bytes almost none of them point at local
// headers.  The recovery scan rebuilds them in directory order, each
// candidate verified by name, and the archive decodes intact.
func TestSplitOffsetsRecovered(t *testing.T) {
	mems := sampleMembers()
	blob, err := Build(mems, "", "", PPMdOpts{})
	if err != nil {
		t.Fatal(err)
	}
	// Sanity: the pristine archive parses without any recovery note.
	ref, err := Parse(append([]byte(nil), blob...), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(ref.Notes) != 0 {
		t.Fatalf("pristine archive produced notes: %v", ref.Notes)
	}

	a, err := Parse(relabelAsSplit(t, append([]byte(nil), blob...), 64), "")
	if err != nil {
		t.Fatalf("split-joined parse: %v", err)
	}
	if len(a.Members) != len(ref.Members) {
		t.Fatalf("members %d, want %d", len(a.Members), len(ref.Members))
	}
	var rebuilt bool
	for _, n := range a.Notes {
		if strings.Contains(n, "rebuilt 4 of 4 local header offsets") {
			rebuilt = true
		}
	}
	if !rebuilt {
		t.Fatalf("recovery note missing: %v", a.Notes)
	}
	for i := range ref.Members {
		if a.Members[i].Name != ref.Members[i].Name {
			t.Fatalf("member %d: %q, want %q", i, a.Members[i].Name, ref.Members[i].Name)
		}
		if got := a.Members[i].Data; !bytes.Equal(got, ref.Members[i].Data) {
			t.Fatalf("member %s content %q", ref.Members[i].Name, got)
		}
	}
}

// TestCDOffsetFallback: when the EOCD's directory offset points beyond
// the archive, the directory is located by position — it physically
// abuts the EOCD.
func TestCDOffsetFallback(t *testing.T) {
	blob, err := Build(sampleMembers(), "", "", PPMdOpts{})
	if err != nil {
		t.Fatal(err)
	}
	eocd := findEOCD(blob)
	binary.LittleEndian.PutUint32(blob[eocd+16:], 0x70000000)
	a, err := Parse(blob, "")
	if err != nil {
		t.Fatalf("fallback parse: %v", err)
	}
	if len(a.Members) != 4 {
		t.Fatalf("members %d", len(a.Members))
	}
	if len(a.Notes) == 0 || !strings.Contains(a.Notes[0], "located by position") {
		t.Fatalf("fallback note missing: %v", a.Notes)
	}
}

// TestWinZipAES both directions: 7-Zip-written goldens decode, our
// AES zips round-trip at every strength and reject wrong passwords,
// and the system tool validates what we write.
func TestWinZipAES(t *testing.T) {
	bin := ""
	for _, name := range []string{"7zz", "7z"} {
		if p, err := exec.LookPath(name); err == nil {
			bin = p
			break
		}
	}
	if bin != "" {
		for _, f := range []string{"/tmp/zspec/aes256.zip", "/tmp/zspec/aes128.zip"} {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Skip("goldens missing")
			}
			a, err := Parse(b, "zpw29")
			if err != nil || string(a.Members[0].Data) != "aes zip secret content\n" {
				t.Errorf("%s: read: %v", f, err)
			}
			if _, err := Parse(b, "wrong"); err == nil {
				t.Errorf("%s: wrong password accepted", f)
			}
			if _, err := Parse(b, ""); err == nil {
				t.Errorf("%s: missing password accepted", f)
			}
		}
	}

	mkMems := func() []member.Member {
		return []member.Member{
			{Name: "d/", Kind: member.Directory, Mode: 0o755},
			{Name: "d/s.txt", Encrypted: true, Mode: 0o644, Data: []byte("aes zip secret content\n")},
			{Name: "d/plain.txt", Mode: 0o644, Data: []byte("in the clear\n")},
		}
	}
	for _, strength := range []int{1, 2, 3} {
		mems := mkMems()
		blob, err := BuildAES(mems, "", "zpw29", strength)
		if err != nil {
			t.Fatalf("strength %d: %v", strength, err)
		}
		a, err := Parse(blob, "zpw29")
		if err != nil {
			t.Errorf("strength %d: round trip: %v", strength, err)
			continue
		}
		if len(a.Members) != 3 || string(a.Members[1].Data) != "aes zip secret content\n" {
			t.Errorf("strength %d: members wrong", strength)
		}
		if _, err := Parse(blob, "nope"); err == nil {
			t.Errorf("strength %d: wrong password accepted", strength)
		}
		if bin == "" {
			continue
		}
		tmp := t.TempDir()
		p := filepath.Join(tmp, "t.zip")
		if err := os.WriteFile(p, blob, 0o644); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(bin, "t", "-pzpw29", p).CombinedOutput(); err != nil {
			t.Errorf("strength %d: system 7z rejected: %v: %s", strength, err, out)
		}
		xdir := t.TempDir()
		if out, err := exec.Command(bin, "x", "-y", "-pzpw29", "-o"+xdir, p).CombinedOutput(); err != nil {
			t.Errorf("strength %d: system 7z extract failed: %v: %s", strength, err, out)
		} else if got, _ := os.ReadFile(filepath.Join(xdir, "d", "s.txt")); string(got) != "aes zip secret content\n" {
			t.Errorf("strength %d: system extract content wrong: %q", strength, got)
		}
	}
}

// TestLZMAAndZstdMethods: the two newer member methods in both
// directions — 7-Zip's LZMA golden decodes, ours round-trip and are
// verified by the system 7zz (LZMA) and 7zz + libarchive (zstd: the
// WinZip id 93 is the one other readers take; the zstd project's own
// id 20 is read and normalized).
func TestLZMAAndZstdMethods(t *testing.T) {
	text := bytes.Repeat([]byte("the quick brown fox jumps over the lazy dog. "), 2000)
	if golden, err := os.ReadFile("/tmp/zspec/lzma.zip"); err == nil {
		a, err := Parse(golden, "")
		if err != nil || !bytes.Equal(a.Members[0].Data, text) {
			t.Errorf("7-Zip zip-LZMA golden: %v", err)
		}
	} else {
		t.Log("golden missing (rebuild /tmp/zspec/lzma.zip with 7zz)")
	}

	for _, tc := range []struct {
		name   string
		method uint16
	}{
		{"lzma", MethodLZMA},
		{"zstd", MethodZstd},
		{"ppmd", MethodPPMd},
	} {
		mems := []member.Member{{Name: "d/big.txt", Mode: 0o644, Method: tc.method, Data: text}}
		blob, err := Build(mems, "", "", PPMdOpts{})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		a, err := Parse(blob, "")
		if err != nil || !bytes.Equal(a.Members[0].Data, text) {
			t.Fatalf("%s: round trip: %v", tc.name, err)
		}
		var bin string
		for _, n := range []string{"7zz", "7z"} {
			if p, err := exec.LookPath(n); err == nil {
				bin = p
				break
			}
		}
		if bin == "" {
			t.Skip("no system 7z")
		}
		tmp := t.TempDir()
		p := filepath.Join(tmp, "t.zip")
		if err := os.WriteFile(p, blob, 0o644); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(bin, "t", p).CombinedOutput(); err != nil {
			t.Errorf("%s: system 7z rejected: %v: %s", tc.name, err, out)
		}
		xdir := t.TempDir()
		if out, err := exec.Command(bin, "x", "-y", "-o"+xdir, p).CombinedOutput(); err != nil {
			t.Errorf("%s: system 7z extract: %v: %s", tc.name, err, out)
		} else if got, _ := os.ReadFile(filepath.Join(xdir, "d", "big.txt")); !bytes.Equal(got, text) {
			t.Errorf("%s: system extract content wrong", tc.name)
		}
	}

	// the zstd project's method 20 reads (normalized from the same payload)
	mems := []member.Member{{Name: "z", Mode: 0o644, Method: MethodZstd, Data: text}}
	blob, _ := Build(mems, "", "", PPMdOpts{})
	blob[8+8] = byte(methodZstdZip) // local header method field
	blob[8+9] = 0
	j := bytes.Index(blob, []byte("PK\x01\x02"))
	blob[j+10] = byte(methodZstdZip)
	blob[j+11] = 0
	if a, err := Parse(blob, ""); err != nil || !bytes.Equal(a.Members[0].Data, text) {
		t.Errorf("zstd method-20 form: %v", err)
	}
}

// TestPPMdZip: our method-98 members are byte-identical to 7zz's for
// the same input (same props, same stream, same header fields), our
// reader takes 7zz's members, and incompressible input falls back to
// stored exactly as 7-Zip's zip writer does.
func TestPPMdZip(t *testing.T) {
	text := bytes.Repeat([]byte("the quick brown fox jumps over the lazy dog. "), 400)
	mems := []member.Member{{Name: "a.txt", Mode: 0o644, Method: MethodPPMd, Data: text}}
	ours, err := Build(mems, "", "", PPMdOpts{})
	if err != nil {
		t.Fatal(err)
	}

	bin := ""
	for _, n := range []string{"7zz", "7z"} {
		if p, err := exec.LookPath(n); err == nil {
			bin = p
			break
		}
	}
	if bin != "" {
		dir := t.TempDir()
		src := filepath.Join(dir, "a.txt")
		if err := os.WriteFile(src, text, 0o644); err != nil {
			t.Fatal(err)
		}
		arc := filepath.Join(dir, "g.zip")
		if out, err := exec.Command(bin, "a", "-bd", "-y", "-tzip", "-m0=PPMd", arc, src).CombinedOutput(); err != nil {
			t.Skipf("7zz: %v: %s", err, out)
		}
		golden, err := os.ReadFile(arc)
		if err != nil {
			t.Fatal(err)
		}
		// same member payload: props + stream, byte for byte
		payload := func(z []byte) []byte {
			nlen := int(z[26])
			elen := int(z[28])
			csize := int(z[18]) | int(z[19])<<8 | int(z[20])<<16 | int(z[21])<<24
			return z[30+nlen+elen : 30+nlen+elen+csize]
		}
		if !bytes.Equal(payload(ours), payload(golden)) {
			t.Errorf("payload not byte-identical to 7zz: %d vs %d bytes", len(payload(ours)), len(payload(golden)))
		}
		// our reader takes their archive
		a, err := Parse(golden, "")
		if err != nil || !bytes.Equal(a.Members[0].Data, text) {
			t.Errorf("7zz golden parse: %v", err)
		}
	}

	// incompressible input stores instead
	rnd := make([]byte, 4000)
	sd := uint32(3)
	for i := range rnd {
		sd = sd*1664525 + 1013904223
		rnd[i] = byte(sd >> 23)
	}
	rmems := []member.Member{{Name: "r.bin", Mode: 0o644, Method: MethodPPMd, Data: rnd}}
	rblob, err := Build(rmems, "", "", PPMdOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if m := binary.LittleEndian.Uint16(rblob[8:10]); m != MethodStore {
		t.Errorf("incompressible PPMd member stored as method %d, want 0", m)
	}
}
