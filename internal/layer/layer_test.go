/*
Copyright (C) Philip Schlump, 2012-2026.

BSD 3 Clause Licensed.
*/

package layer_test

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/pschlump/xtar/internal/layer"
	"github.com/pschlump/xtar/internal/sniff"
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

func TestStreamRoundTrip(t *testing.T) {
	orig := []byte(strings.Repeat("stream me, stream me, ", 500) + "\x00\x01\x02\xff")
	for _, name := range []string{"gzip", "bzip2", "compress", "lz4", "zlib", "deflate"} {
		var buf bytes.Buffer
		w, err := layer.NewWriter(name, &buf)
		if err != nil {
			t.Fatalf("%s writer: %v", name, err)
		}
		data := orig
		for len(data) > 0 {
			n := min(777, len(data))
			if _, err := w.Write(data[:n]); err != nil {
				t.Fatalf("%s write: %v", name, err)
			}
			data = data[n:]
		}
		if err := w.Close(); err != nil {
			t.Fatalf("%s close: %v", name, err)
		}

		r, err := layer.NewReader(name, bytes.NewReader(buf.Bytes()))
		if err != nil {
			t.Fatalf("%s reader: %v", name, err)
		}
		got, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			t.Fatalf("%s read: %v", name, err)
		}
		if !bytes.Equal(got, orig) {
			t.Errorf("%s streaming round trip mismatch (%d vs %d bytes)", name, len(got), len(orig))
		}
	}
}

func TestStreamCrossWholeBuffer(t *testing.T) {
	data := []byte(strings.Repeat("cross the halves, ", 300))
	for _, name := range []string{"gzip", "bzip2", "compress", "lz4", "zlib", "deflate"} {
		// Streaming writer -> whole-buffer Expand.
		var buf bytes.Buffer
		w, _ := layer.NewWriter(name, &buf)
		w.Write(data)
		w.Close()
		if back, err := layer.Expand(name, buf.Bytes()); err != nil || !bytes.Equal(back, data) {
			t.Errorf("%s: whole-buffer Expand cannot read streaming output (err %v)", name, err)
		}

		// Whole-buffer Compress -> streaming reader.
		comp, err := layer.Compress(name, data)
		if err != nil {
			t.Fatalf("%s compress: %v", name, err)
		}
		r, err := layer.NewReader(name, bytes.NewReader(comp))
		if err != nil {
			t.Fatalf("%s reader: %v", name, err)
		}
		got, err := io.ReadAll(r)
		r.Close()
		if err != nil || !bytes.Equal(got, data) {
			t.Errorf("%s: streaming reader cannot read whole-buffer output (err %v)", name, err)
		}
	}
}

func TestStreamBzip2Levels(t *testing.T) {
	data := []byte(strings.Repeat("leveled abcabcabcabcabcabc", 200))
	for _, lvl := range []int{1, 5, 9, 0, 10} { // 0 and 10 fall back to the default
		var buf bytes.Buffer
		w, err := layer.NewWriterLevel("bzip2", &buf, lvl)
		if err != nil {
			t.Fatalf("level %d: %v", lvl, err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatalf("level %d write: %v", lvl, err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("level %d close: %v", lvl, err)
		}
		r, err := layer.NewReader("bzip2", bytes.NewReader(buf.Bytes()))
		if err != nil {
			t.Fatalf("level %d reader: %v", lvl, err)
		}
		got, err := io.ReadAll(r)
		r.Close()
		if err != nil || !bytes.Equal(got, data) {
			t.Errorf("level %d: round trip failed (err %v)", lvl, err)
		}
	}
}

func TestStreamTruncatedAndUnknown(t *testing.T) {
	var buf bytes.Buffer
	w, _ := layer.NewWriter("gzip", &buf)
	w.Write([]byte("truncate this stream"))
	w.Close()
	r, _ := layer.NewReader("gzip", bytes.NewReader(buf.Bytes()[:buf.Len()-3]))
	if _, err := io.ReadAll(r); err == nil {
		t.Error("truncated gzip streamed without error")
	}

	for _, fn := range []func() error{
		func() error { _, err := layer.NewReader("nope", strings.NewReader("")); return err },
		func() error { _, err := layer.NewWriter("nope", io.Discard); return err },
		func() error { _, err := layer.NewWriterLevel("nope", io.Discard, 1); return err },
	} {
		if err := fn(); err == nil {
			t.Error("unknown codec: want error")
		}
	}
}

func TestOpenPeels(t *testing.T) {
	tar := make([]byte, 2048)
	copy(tar[257:], "ustar\x00") // enough for sniff to call it a tar

	// No layers: codecs empty, payload sniffed directly.
	rc, codecs, res, err := layer.Open(bytes.NewReader(tar))
	if err != nil {
		t.Fatal(err)
	}
	if len(codecs) != 0 || res.Format != "tar" {
		t.Fatalf("plain: codecs=%v res=%+v", codecs, res)
	}
	got, err := io.ReadAll(rc)
	if err != nil || len(got) != len(tar) {
		t.Fatalf("plain read: %d bytes, err %v", len(got), err)
	}
	rc.Close()

	// Nested: gzip(bzip2(tar)) peels both, outermost first.
	inner, err := layer.Compress("bzip2", tar)
	if err != nil {
		t.Fatal(err)
	}
	outer, err := layer.Compress("gzip", inner)
	if err != nil {
		t.Fatal(err)
	}
	rc, codecs, res, err = layer.Open(bytes.NewReader(outer))
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	if len(codecs) != 2 || codecs[0] != "gzip" || codecs[1] != "bzip2" {
		t.Fatalf("nested codecs: %v", codecs)
	}
	if res.Kind != sniff.Unknown && res.Format != "tar" && res.Format != "" {
		t.Fatalf("nested sniff: %+v", res)
	}
	got, err = io.ReadAll(rc)
	if err != nil {
		t.Fatalf("nested read: %v", err)
	}
	if !bytes.Equal(got, tar) {
		t.Fatalf("nested peel lost data (%d bytes)", len(got))
	}
}

func TestOpenEmptyAndGarbage(t *testing.T) {
	rc, codecs, res, err := layer.Open(bytes.NewReader(nil))
	if err != nil {
		t.Fatal(err)
	}
	rc.Close()
	if len(codecs) != 0 || res.Kind != sniff.Unknown {
		t.Fatalf("empty: codecs=%v res=%+v", codecs, res)
	}

	rc, codecs, res, err = layer.Open(strings.NewReader("definitely not an archive"))
	if err != nil {
		t.Fatal(err)
	}
	rc.Close()
	if len(codecs) != 0 || res.Kind != sniff.Unknown {
		t.Fatalf("garbage: codecs=%v res=%+v", codecs, res)
	}
}
