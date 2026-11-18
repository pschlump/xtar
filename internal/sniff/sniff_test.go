/*
Copyright (C) Philip Schlump, 2012-2026.

MIT Licensed.
*/

package sniff_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/pschlump/pluto/bzip2"
	"github.com/pschlump/pluto/compress_z"
	"github.com/pschlump/pluto/gzip"
	"github.com/pschlump/pluto/lz4"
	"github.com/pschlump/xtar/internal/member"
	"github.com/pschlump/xtar/internal/sniff"
	"github.com/pschlump/xtar/internal/tarfmt"
)

func TestDetectCodecs(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want string
	}{
		{"gzip", gzip.Compress([]byte("hello")), "gzip"},
		{"compress", compress_z.Compress([]byte("hello")), "compress"},
		{"bzip2", bzip2.Compress([]byte("hello")), "bzip2"},
		{"lz4", lz4.Compress([]byte("hello")), "lz4"},
		{"zip", []byte("PK\x03\x04rest"), "zip"},
		{"zip-empty", []byte("PK\x05\x06" + "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), "zip"},
		{"cpio-newc", []byte("07070100000000"), "cpio"},
		{"cpio-odc", []byte("070707000000"), "cpio"},
		{"cpio-binary", []byte{0xc7, 0x71, 0, 0}, "cpio"},
		{"xz", []byte{0xfd, '7', 'z', 'X', 'Z', 0x00, 1, 2}, "xz"},
		{"zstd", []byte{0x28, 0xb5, 0x2f, 0xfd, 0, 0}, "zstd"},
		{"7z", []byte("7z\xbc\xaf\x27\x1c"), "7z"},
		{"rar", []byte("Rar!\x1a\x07\x00"), "rar"},
		{"unknown", []byte("just some text"), ""},
		{"unknown-bin", []byte{0x89, 'P', 'N', 'G'}, ""},
	}
	for _, c := range cases {
		got := sniff.Detect(c.data)
		if got.Format != c.want {
			t.Errorf("%s: got %q (kind %d), want %q", c.name, got.Format, got.Kind, c.want)
		}
	}
}

func TestDetectTarVariants(t *testing.T) {
	mems := []member.Member{{Name: "f", Kind: member.Regular, Mode: 0o644, Data: []byte("data"), Size: 4, ModTime: time.Unix(1731400000, 0)}}
	for _, format := range []string{"gnu", "ustar", "pax"} {
		blob, err := tarfmt.Build(format, mems)
		if err != nil {
			t.Fatalf("build %s: %v", format, err)
		}
		got := sniff.Detect(blob)
		if got.Format != "tar" || got.Kind != sniff.Container {
			t.Errorf("format %s: got %q kind %d, want tar container", format, got.Format, got.Kind)
		}
	}
	// empty tar: two zero blocks
	got := sniff.Detect(make([]byte, 1024))
	if got.Format != "tar" || got.Variant != "empty" {
		t.Errorf("empty tar: got %+v", got)
	}
	// v7: header with no magic but a valid checksum
	got = sniff.Detect(v7Tar("oldfile"))
	if got.Format != "tar" || got.Variant != "v7" {
		t.Errorf("v7 tar: got %+v", got)
	}
}

// v7Tar builds a pre-POSIX header: octal fields, no magic, checksum.
func v7Tar(name string) []byte {
	var blk [512]byte
	copy(blk[0:100], name)
	copy(blk[100:108], "0000644\x00")
	copy(blk[108:116], "0001750\x00")
	copy(blk[116:124], "0000020\x00")
	copy(blk[124:136], "00000000005\x00")
	copy(blk[136:148], "14400000000\x00")
	blk[156] = '0'
	var sum int64
	for i := 0; i < 512; i++ {
		if i >= 148 && i < 156 {
			sum += ' '
		} else {
			sum += int64(blk[i])
		}
	}
	copy(blk[148:156], fmt.Sprintf("%06o", sum))
	blk[154] = 0
	blk[155] = ' '
	out := append([]byte{}, blk[:]...)
	out = append(out, "hello"...)
	out = append(out, make([]byte, 512-5)...)
	out = append(out, make([]byte, 1024)...)
	return out
}
