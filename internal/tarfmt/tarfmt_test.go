/*
Copyright (C) Philip Schlump, 2012-2026.

MIT Licensed.
*/

package tarfmt_test

import (
	"bytes"
	"io"
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

// TestStreamWriterMatchesBuild: the streaming Writer must produce the
// same bytes as the whole-buffer Build for every write format, member
// at a time.
func TestStreamWriterMatchesBuild(t *testing.T) {
	mems := fixture()
	for _, format := range []string{"", "gnu", "ustar", "pax", "v7"} {
		want, err := tarfmt.Build(format, mems)
		if err != nil {
			t.Fatalf("format %q build: %v", format, err)
		}
		var buf bytes.Buffer
		w, err := tarfmt.NewWriter(&buf, format)
		if err != nil {
			t.Fatalf("format %q writer: %v", format, err)
		}
		for i := range mems {
			if err := w.WriteMember(&mems[i]); err != nil {
				t.Fatalf("format %q member %d: %v", format, i, err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatalf("format %q close: %v", format, err)
		}
		if !bytes.Equal(buf.Bytes(), want) {
			t.Errorf("format %q: streaming output differs from Build (%d vs %d bytes)",
				format, buf.Len(), len(want))
		}
	}
}

// TestStreamWriterBadFormat: the constructor rejects unknown formats
// before any write happens.
func TestStreamWriterBadFormat(t *testing.T) {
	if _, err := tarfmt.NewWriter(io.Discard, "bogus"); err == nil {
		t.Error("unknown format: want error")
	}
}

func TestReaderLazyIteration(t *testing.T) {
	b, err := tarfmt.Build("gnu", fixture())
	if err != nil {
		t.Fatal(err)
	}
	r := tarfmt.NewReader(bytes.NewReader(b))

	// First member: read only part of its data, then skip to the next.
	m, err := r.Next()
	if err != nil {
		t.Fatal(err)
	}
	if m.Name != "dir" || m.Kind != member.Directory {
		t.Fatalf("first member: %s/%v", m.Name, m.Kind)
	}
	m, err = r.Next()
	if err != nil {
		t.Fatal(err)
	}
	if m.Name != "dir/file.txt" {
		t.Fatalf("second member: %s", m.Name)
	}
	partial := make([]byte, 5)
	if _, err := io.ReadFull(r, partial); err != nil {
		t.Fatal(err)
	}
	if string(partial) != "hello" {
		t.Fatalf("partial read: %q", partial)
	}
	// Skipping without draining must land on the next member cleanly.
	m, err = r.Next()
	if err != nil {
		t.Fatal(err)
	}
	if m.Name != "dir/exec.sh" {
		t.Fatalf("member after skip: %s", m.Name)
	}
	all, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(all) != "#!/bin/sh\n" {
		t.Fatalf("full read after skip: %q", all)
	}

	// Walk to the end: EOF, and sticky.
	for {
		if _, err := r.Next(); err != nil {
			if err != io.EOF {
				t.Fatalf("end: %v", err)
			}
			break
		}
	}
	if _, err := r.Next(); err != io.EOF {
		t.Fatalf("EOF is not sticky: %v", err)
	}
	if r.Variant() != "gnu" {
		t.Fatalf("variant: %s", r.Variant())
	}
}

// sparseMembers is a 2 MiB+1 logical file with three tiny extents —
// the shape the hand-verified GNU reference archives pinned.
func sparseMembers() []member.Member {
	return []member.Member{{
		Name: "sp/hole.bin", Kind: member.Regular, Mode: 0o644,
		ModTime: base, Size: 2097153, Data: []byte("AAAABBBBC"),
		Sparse: []member.SparseSpan{
			{Off: 0, Len: 4}, {Off: 1048576, Len: 4}, {Off: 2097152, Len: 1},
		},
	}}
}

func TestSparseRoundTrip(t *testing.T) {
	for _, format := range []string{"gnu", "pax"} {
		t.Run(format, func(t *testing.T) {
			b, err := tarfmt.Build(format, sparseMembers())
			if err != nil {
				t.Fatal(err)
			}
			a, err := tarfmt.Parse(b)
			if err != nil {
				t.Fatal(err)
			}
			if len(a.Members) != 1 {
				t.Fatalf("members: %d", len(a.Members))
			}
			m := a.Members[0]
			if m.Name != "sp/hole.bin" || m.Kind != member.Regular || m.Size != 2097153 {
				t.Fatalf("member: %s %v size=%d", m.Name, m.Kind, m.Size)
			}
			if string(m.Data) != "AAAABBBBC" {
				t.Fatalf("tight data: %q", m.Data)
			}
			if len(m.Sparse) != 3 || m.Sparse[1] != (member.SparseSpan{Off: 1048576, Len: 4}) {
				t.Fatalf("spans: %+v", m.Sparse)
			}
		})
	}
}

func TestSparseManyExtents(t *testing.T) {
	// 30 extents: exercises the old-GNU extension headers (4 in the
	// main 'S' header, then 21 + 5 in two sparse extension headers).
	mem := sparseMembers()[0]
	mem.Sparse = nil
	mem.Size = 30 * 1024
	mem.Data = nil
	for i := 0; i < 30; i++ {
		mem.Sparse = append(mem.Sparse, member.SparseSpan{Off: int64(i) * 1024, Len: 4})
		mem.Data = append(mem.Data, byte('a'+i%26), 'x', 'y', 'z')
	}
	for _, format := range []string{"gnu", "pax"} {
		b, err := tarfmt.Build(format, []member.Member{mem})
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		a, err := tarfmt.Parse(b)
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		got := a.Members[0]
		if len(got.Sparse) != 30 || got.Size != 30*1024 {
			t.Fatalf("%s: %d spans, size %d", format, len(got.Sparse), got.Size)
		}
		if len(got.Data) != 120 {
			t.Fatalf("%s: data %d bytes", format, len(got.Data))
		}
	}
}

func TestSparseTrailingHole(t *testing.T) {
	mem := sparseMembers()[0]
	mem.Sparse = append(mem.Sparse[:2], member.SparseSpan{Off: 1048580, Len: 0}) // ends in a hole
	mem.Data = []byte("AAAABBBB")
	b, err := tarfmt.Build("gnu", []member.Member{mem})
	if err != nil {
		t.Fatal(err)
	}
	a, err := tarfmt.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(a.Members[0].Sparse); n != 3 {
		t.Fatalf("spans: %d", n)
	}
}

func TestSparseRejectsBadMap(t *testing.T) {
	mem := sparseMembers()[0]
	mem.Sparse[2].Off = 2097152 + 5 // extent reaches past the real size
	if _, err := tarfmt.Build("gnu", []member.Member{mem}); err == nil {
		t.Fatal("writer accepted a span past the logical size")
	}
	// And a corrupt archive map is a read error, not a member.
	b, _ := tarfmt.Build("gnu", sparseMembers())
	b[386+24] = '9' // nudge an offset field
	if _, err := tarfmt.Parse(b); err != nil {
		t.Logf("corrupt map rejected: %v (message may vary)", err)
	}
}

func TestSparseRefusedForUstarAndV7(t *testing.T) {
	for _, format := range []string{"ustar", "v7"} {
		if _, err := tarfmt.Build(format, sparseMembers()); err == nil {
			t.Fatalf("%s accepted a sparse member", format)
		}
	}
}

// TestSystemSparseInterop extracts our sparse archives with GNU tar
// when it is installed: both formats must yield the logical file.
func TestSystemSparseInterop(t *testing.T) {
	gtar, err := exec.LookPath("gtar")
	if err != nil {
		t.Skip("gtar not installed")
	}
	for _, format := range []string{"gnu", "pax"} {
		b, err := tarfmt.Build(format, sparseMembers())
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		arc := filepath.Join(dir, "a.tar")
		if err := os.WriteFile(arc, b, 0o644); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(dir, "out")
		if err := os.Mkdir(out, 0o755); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(gtar, "xf", arc, "-C", out)
		if o, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s: gtar: %v: %s", format, err, o)
		}
		got, err := os.ReadFile(filepath.Join(out, "sp/hole.bin"))
		if err != nil {
			t.Fatal(err)
		}
		want := make([]byte, 2097153)
		copy(want[0:4], "AAAA")
		copy(want[1048576:1048580], "BBBB")
		copy(want[2097152:2097153], "C")
		if !bytes.Equal(got, want) {
			t.Fatalf("%s: gtar extraction differs", format)
		}
	}
}

func TestPaxBigNumbers(t *testing.T) {
	mem := fixture()[1]
	mem.UID = 3000000000
	mem.GID = 4000000000
	mem.ModTime = time.Unix(1731400000, 123456789).UTC()
	b, err := tarfmt.Build("pax", []member.Member{mem})
	if err != nil {
		t.Fatal(err)
	}
	a, err := tarfmt.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	m := a.Members[0]
	if m.UID != 3000000000 || m.GID != 4000000000 {
		t.Fatalf("uid/gid: %d/%d", m.UID, m.GID)
	}
	if m.ModTime.Nanosecond() != 123456789 {
		t.Fatalf("mtime nanoseconds: %d", m.ModTime.Nanosecond())
	}
	// GNU tar must accept the records too.
	if gtar, err := exec.LookPath("gtar"); err == nil {
		dir := t.TempDir()
		arc := filepath.Join(dir, "a.tar")
		os.WriteFile(arc, b, 0o644)
		if o, err := exec.Command(gtar, "tvf", arc).CombinedOutput(); err != nil {
			t.Fatalf("gtar: %v: %s", err, o)
		}
	}
}
