/*
Copyright (C) Philip Schlump, 2012-2026.

MIT Licensed.
*/

package cli

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/pschlump/pluto/bzip2"
	"github.com/pschlump/pluto/crc"
	"github.com/pschlump/pluto/deflate"
	"github.com/pschlump/pluto/gzip"
	"github.com/pschlump/pluto/lz4"
	"github.com/pschlump/pluto/lzma"
	"github.com/pschlump/pluto/xz"
	"github.com/pschlump/pluto/zstd"
)

// benchCorpus is a synthetic mixture: compressible text, a run, and
// pseudorandom noise, sized to a few MiB so timings settle.
func benchCorpus() []byte {
	const textN = 1 << 20
	corpus := make([]byte, 0, 4*textN)
	unit := []byte("the quick brown fox jumps over the lazy dog; pack my box with five dozen liquor jugs. ")
	s := uint32(1)
	for len(corpus) < textN {
		s = s*1664525 + 1013904223
		corpus = append(corpus, unit[s%uint32(len(unit))])
		if s&7 == 0 {
			corpus = append(corpus, unit...)
		}
	}
	runs := make([]byte, textN/2)
	for i := range runs {
		runs[i] = 7
	}
	noise := make([]byte, textN)
	for i := range noise {
		s = s*1664525 + 1013904223
		noise[i] = byte(s >> 23)
	}
	return append(append(corpus, runs...), noise...)
}

// SevenzBench is `7z b`: compress and decompress the synthetic corpus
// through every codec and report throughput.
func SevenzBench(e *env) int {
	data := benchCorpus()
	crcTab := crc.MakeTable32(0xEDB88320)
	fmt.Printf("%-8s %11s %13s %9s\n", "Codec", "Compressed", "MB/s comp", "MB/s dec")
	type codec struct {
		name string
		comp func([]byte) []byte
		dec  func([]byte) []byte
	}
	codecs := []codec{
		{"deflate", deflate.Compress, func(b []byte) []byte { o, _ := deflate.Expand(b); return o }},
		{"gzip", gzip.Compress, gzip.Expand},
		{"bzip2", bzip2.Compress, bzip2.Expand},
		{"lz4", lz4.Compress, lz4.Expand},
		{"lzma", lzma.Compress, lzma.Expand},
		{"xz", xz.Compress, xz.Expand},
		{"zstd", zstd.Compress, zstd.Expand},
	}
	mib := float64(len(data)) / (1 << 20)
	for _, c := range codecs {
		start := time.Now()
		z := c.comp(data)
		compTime := time.Since(start)
		start = time.Now()
		back := c.dec(z)
		decTime := time.Since(start)
		if !sameBytes(back, data) {
			return e.fatal("%s: benchmark round trip mismatch", c.name)
		}
		fmt.Printf("%-8s %11d %13.1f %9.1f\n", c.name, len(z),
			mib/compTime.Seconds(), mib/decTime.Seconds())
	}
	start := time.Now()
	crc.Checksum32(data, crcTab)
	fmt.Printf("%-8s %11s %13s %9.1f\n", "crc32", "-", "-",
		mib/time.Since(start).Seconds())
	start = time.Now()
	sha256.Sum256(data)
	fmt.Printf("%-8s %11s %13s %9.1f\n", "sha256", "-", "-",
		mib/time.Since(start).Seconds())
	return exitOK
}

func sameBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// SevenzHash is `7z h`: CRC-32 and SHA-256 of the named files.
func SevenzHash(e *env, args []string) int {
	files := args
	if len(files) == 0 {
		files = []string{"*"}
	}
	for _, name := range files {
		fi, err := os.Stat(name)
		if err != nil {
			return e.fatal("%v", err)
		}
		if fi.IsDir() {
			// 7z h over a directory hashes its files, one line each
			entries, err := os.ReadDir(name)
			if err != nil {
				return e.fatal("%v", err)
			}
			for _, de := range entries {
				if de.IsDir() {
					continue
				}
				if err := hashFile(name + "/" + de.Name()); err != nil {
					return e.fatal("%v", err)
				}
			}
			continue
		}
		if err := hashFile(name); err != nil {
			return e.fatal("%v", err)
		}
	}
	return exitOK
}

func hashFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	tab := crc.MakeTable32(0xEDB88320)
	h := sha256.New()
	var c32 uint32
	buf := make([]byte, 1<<16)
	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			c32 = crc.Update32(c32, tab, buf[:n])
			h.Write(buf[:n])
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return rerr
		}
	}
	fmt.Printf("%08x  %x  %12d  %s\n", c32, h.Sum(nil), fi.Size(), path)
	return nil
}
