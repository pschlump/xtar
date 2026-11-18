/*
Copyright (C) Philip Schlump, 2012-2026.

MIT Licensed.
*/

package walk

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestReadSparseScan(t *testing.T) {
	dir := t.TempDir()

	// Dense file: no spans.
	dense := filepath.Join(dir, "dense.bin")
	os.WriteFile(dense, []byte("solid data, no holes"), 0o644)
	_, spans, err := readSparse(dense, int64(len("solid data, no holes")))
	if err != nil {
		t.Fatal(err)
	}
	if spans != nil {
		t.Fatalf("dense file got spans %v", spans)
	}

	// Zero blocks between data blocks: three extents, block-granular,
	// plus the trailing-hole marker (the file ends with a zero block).
	big := make([]byte, 6*blockSize)
	copy(big[0:5], "AAAA")
	copy(big[2*blockSize:2*blockSize+5], "BBBB")
	copy(big[4*blockSize:4*blockSize+1], "C")
	holed := filepath.Join(dir, "holed.bin")
	if err := os.WriteFile(holed, big, 0o644); err != nil {
		t.Fatal(err)
	}
	data, spans, err := readSparse(holed, int64(len(big)))
	if err != nil {
		t.Fatal(err)
	}
	if len(spans) != 4 { // three extents + the trailing-hole marker
		t.Fatalf("spans: %+v", spans)
	}
	// Block-granular extents: each data block is stored whole (GNU's
	// raw scanner has no finer resolution).
	want := append(append(append([]byte{}, big[0:blockSize]...), big[2*blockSize:3*blockSize]...), big[4*blockSize:5*blockSize]...)
	if !bytes.Equal(data, want) {
		t.Fatalf("extent data: %d bytes (want %d)", len(data), len(want))
	}
	if spans[0].Off != 0 || spans[0].Len != blockSize || spans[1].Off != 2*blockSize {
		t.Fatalf("span layout: %+v", spans)
	}
	if spans[3].Len != 0 || spans[3].Off != 6*blockSize {
		t.Fatalf("trailing marker: %+v", spans[3])
	}

	// All zeros: one zero-length extent at the end.
	zeros := filepath.Join(dir, "zeros.bin")
	if err := os.WriteFile(zeros, make([]byte, 5*blockSize), 0o644); err != nil {
		t.Fatal(err)
	}
	data, spans, err = readSparse(zeros, 5*blockSize)
	if err != nil {
		t.Fatal(err)
	}
	if len(spans) != 1 || spans[0].Len != 0 || spans[0].Off != 5*blockSize {
		t.Fatalf("all-zero spans: %+v", spans)
	}
	if len(data) != 0 {
		t.Fatalf("all-zero data: %d bytes", len(data))
	}

	// Tiny files are never sparse.
	tiny := filepath.Join(dir, "tiny.bin")
	os.WriteFile(tiny, make([]byte, 100), 0o644)
	_, spans, err = readSparse(tiny, 100)
	if err != nil || spans != nil {
		t.Fatalf("tiny: spans=%v err=%v", spans, err)
	}
}
