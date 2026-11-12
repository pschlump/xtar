/*
Copyright (C) Philip Schlump, 2012-2026.

BSD 3 Clause Licensed.
*/

package layer_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/pschlump/xtar/internal/layer"
)

func TestRoundTrip(t *testing.T) {
	data := []byte(strings.Repeat("the quick brown fox jumps over the lazy dog ", 40) + "\x00\x01\x02\xff")
	for _, name := range []string{"gzip", "bzip2", "compress", "lz4", "zlib"} {
		c, ok := layer.ByName(name)
		if !ok {
			t.Fatalf("codec %q not registered", name)
		}
		comp, err := c.Compress(data)
		if err != nil {
			t.Fatalf("%s compress: %v", name, err)
		}
		if len(comp) == 0 {
			t.Fatalf("%s compress produced nothing", name)
		}
		back, err := c.Expand(comp)
		if err != nil {
			t.Fatalf("%s expand: %v", name, err)
		}
		if !bytes.Equal(back, data) {
			t.Errorf("%s round trip mismatch (%d vs %d bytes)", name, len(back), len(data))
		}
	}
}

func TestCorruptErrors(t *testing.T) {
	c, _ := layer.ByName("gzip")
	comp, err := c.Compress([]byte("some data"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Expand(comp[:5]); err == nil {
		t.Error("truncated gzip expanded without error")
	}
	if _, err := c.Expand([]byte("not gzip at all")); err == nil {
		t.Error("garbage expanded without error")
	}
}

func TestBzip2Levels(t *testing.T) {
	c, _ := layer.ByName("bzip2")
	data := []byte(strings.Repeat("abcabcabcabcabcabcabc", 100))
	for lvl := 1; lvl <= 9; lvl++ {
		comp, err := c.CompressLevel(data, lvl)
		if err != nil {
			t.Fatalf("level %d: %v", lvl, err)
		}
		back, err := c.Expand(comp)
		if err != nil {
			t.Fatalf("level %d expand: %v", lvl, err)
		}
		if !bytes.Equal(back, data) {
			t.Errorf("level %d round trip mismatch", lvl)
		}
	}
}
