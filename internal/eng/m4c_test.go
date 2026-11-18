/*
Copyright (C) Philip Schlump, 2012-2026.

MIT Licensed.
*/

package eng

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pschlump/xtar/internal/member"
	"github.com/pschlump/xtar/internal/tarfmt"
)

func TestExtractSparse(t *testing.T) {
	base := int64(1731400000)
	sp := member.Member{
		Name: "hole.bin", Kind: member.Regular, Mode: 0o644, ModTime: modTime(base),
		Size: 2097153, Data: []byte("AAAABBBBC"),
		Sparse: []member.SparseSpan{{Off: 0, Len: 4}, {Off: 1048576, Len: 4}, {Off: 2097152, Len: 1}},
	}
	for _, format := range []string{"gnu", "pax"} {
		blob, err := tarfmt.Build(format, []member.Member{sp})
		if err != nil {
			t.Fatal(err)
		}
		a, err := Decode(blob, "")
		if err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(t.TempDir(), "out")
		if err := Extract(a, &ExtractOpts{Dest: dst, Warn: func(string) {}}); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(dst, "hole.bin"))
		if err != nil {
			t.Fatal(err)
		}
		want := make([]byte, 2097153)
		copy(want[0:4], "AAAA")
		copy(want[1048576:1048580], "BBBB")
		copy(want[2097152:2097153], "C")
		if string(got) != string(want) {
			t.Fatalf("%s: extracted layout differs", format)
		}
	}
}

func TestSetEncodingTar(t *testing.T) {
	// A tar whose member name carries a Latin-1 byte (é as 0xE9) —
	// bytes as stored, no declared charset.
	name := "caf" + string([]byte{0xE9}) + ".txt"
	blob, err := tarfmt.Build("gnu", []member.Member{
		{Name: name, Kind: member.Regular, Mode: 0o644, Size: 3, Data: []byte("hi\n")},
	})
	if err != nil {
		t.Fatal(err)
	}
	a, err := Decode(blob, "")
	if err != nil {
		t.Fatal(err)
	}
	if a.Members[0].Name != name {
		t.Fatalf("raw name: %q", a.Members[0].Name)
	}
	if err := a.SetEncoding("iso-8859-1"); err != nil {
		t.Fatal(err)
	}
	if want := "café.txt"; a.Members[0].Name != want {
		t.Fatalf("re-encoded name: %q want %q", a.Members[0].Name, want)
	}
	if err := a.SetEncoding("klingon"); err == nil {
		t.Fatal("unknown charset accepted")
	}
}
