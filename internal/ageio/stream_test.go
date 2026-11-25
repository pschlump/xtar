/*
Copyright (C) Philip Schlump, 2012-2026.

MIT Licensed.
*/

package ageio

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"
)

// genStream is a deterministic, incompressible byte stream of splitmix64
// words — the stand-in for WAL pages and base-backup blocks.  It keeps
// no data: each Read fills the caller's buffer afresh, and every byte
// also goes into sum, so the digest of a stream twice the machine's
// memory is known without holding any of it.  tick runs every 2 MiB.
type genStream struct {
	state uint64
	left  int64
	sum   hash.Hash
	reads int
	tick  func()
}

func newGenStream(n int64, tick func()) *genStream {
	return &genStream{state: 0x243F6A8885A308D3, left: n, sum: sha256.New(), tick: tick}
}

func splitmix64(s *uint64) uint64 {
	*s += 0x9E3779B97F4A7C15
	z := *s
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	return z ^ (z >> 31)
}

func (g *genStream) Read(p []byte) (int, error) {
	if g.left <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > g.left {
		p = p[:g.left]
	}
	var word [8]byte
	for i := 0; i < len(p); i += 8 {
		binary.LittleEndian.PutUint64(word[:], splitmix64(&g.state))
		copy(p[i:], word[:])
	}
	g.left -= int64(len(p))
	g.sum.Write(p)
	if g.reads++; g.tick != nil && g.reads%64 == 0 {
		g.tick()
	}
	return len(p), nil
}

// sizedWriter passes writes through, refusing any larger than one
// encrypted age chunk: proof that no stage ever hands over the whole
// payload in one piece.
type sizedWriter struct {
	w   io.Writer
	n   int64
	max int
}

func (s *sizedWriter) Write(p []byte) (int, error) {
	n, err := s.w.Write(p)
	s.n += int64(n)
	if n > s.max {
		s.max = n
	}
	return n, err
}

func encryptBytes(t *testing.T, plain []byte, rs []age.Recipient) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := Encrypt(&buf, bytes.NewReader(plain), rs); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	return buf.Bytes()
}

func decryptBytes(t *testing.T, cipher []byte, ids []age.Identity) []byte {
	t.Helper()
	var buf bytes.Buffer
	if _, err := Decrypt(&buf, bytes.NewReader(cipher), ids); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	return buf.Bytes()
}

// TestRoundTripSizes: empty input, one byte, both sides of every chunk
// boundary in the first three chunks, and several MiB — each comes
// back byte for byte.
func TestRoundTripSizes(t *testing.T) {
	id := testKey(t)
	sizes := []int{
		0, 1, 2, 62, 1023,
		ChunkSize - 1, ChunkSize, ChunkSize + 1,
		2*ChunkSize - 1, 2 * ChunkSize, 2*ChunkSize + 1,
		3*ChunkSize - 1, 3 * ChunkSize, 3*ChunkSize + 1,
		5<<20 + 1,
	}
	fixed := 0 // header + nonce, as measured on the first size
	for _, size := range sizes {
		plain := make([]byte, size)
		if _, err := io.ReadFull(newGenStream(int64(size), nil), plain); err != nil {
			t.Fatal(err)
		}
		cipher := encryptBytes(t, plain, recipientsOf(id))
		if got := decryptBytes(t, cipher, identitiesOf(id)); !bytes.Equal(got, plain) {
			t.Fatalf("size %d: %d bytes back, plaintext differs", size, len(got))
		}
		// Only the last chunk is short: the payload is the plaintext
		// plus one 16-byte tag per 64 KiB chunk (the empty input is
		// one empty chunk), so overhead minus tags is the constant
		// header and nonce for every size.
		chunks := (size + ChunkSize - 1) / ChunkSize
		if size == 0 {
			chunks = 1
		}
		overhead := len(cipher) - size - 16*chunks
		if overhead <= 16 || overhead > 4096 || (size > 0 && overhead != fixed) {
			t.Errorf("size %d: %d ciphertext bytes is not a %d-byte header and nonce over %d chunked bytes",
				size, len(cipher), overhead, size)
		}
		fixed = overhead
	}
}

// TestCiphertextIsStandardAgeV1: the output is the binary age v1 file
// — its intro, X25519 stanzas, and MAC — not armor, and nothing the
// sniffing table would call another format.
func TestCiphertextIsStandardAgeV1(t *testing.T) {
	a, b := testKey(t), testKey(t)
	plain := []byte("the plaintext that must not survive in the clear\n")
	cipher := encryptBytes(t, plain, recipientsOf(a, b))

	if !bytes.HasPrefix(cipher, []byte("age-encryption.org/v1\n")) {
		t.Fatalf("ciphertext does not start with the age v1 intro: %q", cipher[:40])
	}
	if bytes.Contains(cipher, []byte(plain)) {
		t.Fatal("plaintext is visible in the ciphertext")
	}
	if n := bytes.Count(cipher, []byte("\n-> X25519 ")); n != 2 {
		t.Errorf("%d X25519 stanzas, want one per recipient (2)", n)
	}
	if !bytes.Contains(cipher, []byte("\n--- ")) {
		t.Error("ciphertext lacks the header MAC line")
	}
	for _, alien := range [][]byte{
		[]byte("-----BEGIN AGE ENCRYPTED FILE-----"), // armor
		{0x1f, 0x8b},                 // gzip
		[]byte("PK\x03\x04"),         // zip
		[]byte("7z\xbc\xaf\x27\x1c"), // 7z
	} {
		if bytes.HasPrefix(cipher, alien) {
			t.Errorf("ciphertext starts like another format: %x", alien)
		}
	}
	if len(cipher) > 257 && string(cipher[257:262]) == "ustar" {
		t.Error("ciphertext carries a tar magic")
	}
	// One stanza per recipient; age's own parser accepts the file.
	parsed, err := age.Decrypt(bytes.NewReader(cipher), a)
	if err != nil {
		t.Fatalf("age cannot open our ciphertext: %v", err)
	}
	if rest, err := io.ReadAll(parsed); err != nil || !bytes.Equal(rest, plain) {
		t.Fatalf("age read back %d bytes, err %v", len(rest), err)
	}
}

// TestMultipleRecipientsAndRotation: a file encrypted to two
// recipients opens with either identity alone, and after a rotation an
// identity that lives only in the second identity file still opens
// what was encrypted to it.
func TestMultipleRecipientsAndRotation(t *testing.T) {
	current, recovery, successor := testKey(t), testKey(t), testKey(t)
	dir := t.TempDir()
	plain := []byte("000000010000000000000042 — a WAL segment\n")

	both := encryptBytes(t, plain, recipientsOf(current, recovery))
	for name, id := range map[string]*age.X25519Identity{"current": current, "recovery": recovery} {
		if !bytes.Equal(decryptBytes(t, both, identitiesOf(id)), plain) {
			t.Errorf("%s identity alone could not decrypt", name)
		}
	}

	// Rotation: the old pair, then a file holding only the new key.
	files := []string{
		writeFile(t, filepath.Join(dir, "old.txt"), string(IdentityFile(current, time.Now()))+recovery.String()+"\n"),
		writeFile(t, filepath.Join(dir, "new.txt"), string(IdentityFile(successor, time.Now()))),
	}
	ids, err := LoadIdentities(files)
	if err != nil {
		t.Fatal(err)
	}
	for name, id := range map[string]*age.X25519Identity{"successor": successor, "current": current} {
		cipher := encryptBytes(t, plain, recipientsOf(id))
		if !bytes.Equal(decryptBytes(t, cipher, ids), plain) {
			t.Errorf("after rotation, a file encrypted to the %s key does not open", name)
		}
	}
	oldOnly := identitiesOf(current, recovery)
	cipher := encryptBytes(t, plain, recipientsOf(successor))
	if _, err := Decrypt(io.Discard, bytes.NewReader(cipher), oldOnly); !errors.Is(err, ErrNoIdentityMatch) {
		t.Errorf("the retired identities opened a file encrypted only to the successor: %v", err)
	}
}

// TestFailClosed: every damaged, foreign, or wrongly keyed input is an
// error, and nothing that fails before the payload yields any
// plaintext at all.
func TestFailClosed(t *testing.T) {
	right, other, third := testKey(t), testKey(t), testKey(t)
	plain := make([]byte, 3*ChunkSize+7)
	if _, err := io.ReadFull(newGenStream(int64(len(plain)), nil), plain); err != nil {
		t.Fatal(err)
	}
	full := encryptBytes(t, plain, recipientsOf(right))

	// Layout: header lines, the 16-byte nonce, then the chunks: three
	// full ones and a last one of 7 bytes.
	mac := bytes.Index(full, []byte("\n--- "))
	body := mac + 1 + bytes.IndexByte(full[mac+1:], '\n') + 1
	firstChunk := body + 16
	secondChunk := firstChunk + ChunkSize + 16
	thirdChunk := secondChunk + ChunkSize + 16
	fourthChunk := thirdChunk + ChunkSize + 16
	// flip changes one byte to another valid ASCII one, so a damaged
	// header stays well-formed enough to reach its MAC check.
	flip := func(b []byte, i int) []byte {
		out := bytes.Clone(b)
		if out[i] == 'A' {
			out[i] = 'B'
		} else {
			out[i] = 'A'
		}
		return out
	}

	for _, tc := range []struct {
		name string
		ids  []age.Identity
		in   []byte
		// exactly how much plaintext is delivered before the error:
		// whole authenticated chunks, never a failed one
		wantPrefix int
	}{
		{"wrong identity", identitiesOf(other), full, 0},
		{"wrong of several", identitiesOf(other, third), full, 0},
		{"empty input", identitiesOf(right), nil, 0},
		{"not age (gzip)", identitiesOf(right), append([]byte{0x1f, 0x8b, 0x08}, bytes.Repeat([]byte{7}, 500)...), 0},
		{"truncated header", identitiesOf(right), full[:20], 0},
		{"header without MAC", identitiesOf(right), full[:mac], 0},
		{"modified header MAC", identitiesOf(right), flip(full, mac+20), 0},
		{"garbage header line", identitiesOf(right), []byte("age-encryption.org/v1\ngarbage\n"), 0},
		{"header only", identitiesOf(right), full[:body], 0},
		{"truncated nonce", identitiesOf(right), full[:body+10], 0},
		{"modified nonce", identitiesOf(right), flip(full, body+3), 0},
		{"modified first chunk", identitiesOf(right), flip(full, firstChunk+500), 0},
		{"modified middle chunk", identitiesOf(right), flip(full, secondChunk+500), ChunkSize},
		{"modified final chunk", identitiesOf(right), flip(full, len(full)-1), 3 * ChunkSize},
		{"truncated final chunk", identitiesOf(right), full[:len(full)-1], 3 * ChunkSize},
		{"truncated to one byte of final chunk", identitiesOf(right), full[:fourthChunk+1], 3 * ChunkSize},
		{"truncated mid-chunk", identitiesOf(right), full[:secondChunk+300], ChunkSize},
		{"truncated at chunk boundary", identitiesOf(right), full[:secondChunk], ChunkSize},
		{"truncated to the header's nonce", identitiesOf(right), full[:body+16], 0},
		// The junk joins the short final chunk and spoils its tag.
		{"trailing data", identitiesOf(right), append(bytes.Clone(full), "garbage"...), 3 * ChunkSize},
	} {
		var out bytes.Buffer
		n, err := Decrypt(&out, bytes.NewReader(tc.in), tc.ids)
		if err == nil {
			t.Errorf("%s: decrypted to %d bytes without error", tc.name, n)
			continue
		}
		if n != int64(tc.wantPrefix) {
			t.Errorf("%s: %d plaintext bytes before the error (%v), want %d",
				tc.name, n, err, tc.wantPrefix)
			continue
		}
		// Whatever came out before the failure was intact data only.
		if !bytes.Equal(out.Bytes(), plain[:n]) {
			t.Errorf("%s: the prefix before the error is not the plaintext's own", tc.name)
		}
	}
}

// TestWrongIdentityIsNamed: a non-matching key reports exactly that, so
// the CLI can say "wrong identity" rather than "corrupt file".
func TestWrongIdentityIsNamed(t *testing.T) {
	right, wrong := testKey(t), testKey(t)
	cipher := encryptBytes(t, []byte("payload"), recipientsOf(right))
	if _, err := Decrypt(io.Discard, bytes.NewReader(cipher), identitiesOf(wrong)); !errors.Is(err, ErrNoIdentityMatch) {
		t.Fatalf("wrong identity: %v", err)
	}
	if _, err := Decrypt(io.Discard, bytes.NewReader(cipher), identitiesOf(right, wrong)); err != nil {
		t.Fatalf("the right identity among others: %v", err)
	}
}

// TestSourceReadError: an input that dies mid-stream fails the
// encryption; the partial chunk in hand is not finalized as if the
// input had ended.
func TestSourceReadError(t *testing.T) {
	id := testKey(t)
	plain := make([]byte, ChunkSize+100)
	src := &errReader{data: plain, err: errSource}
	var out bytes.Buffer
	if err := Encrypt(&out, src, recipientsOf(id)); !errors.Is(err, errSource) {
		t.Fatalf("encrypt over a failing source: %v", err)
	}
	// What was written is header, nonce, and whole chunks only; it
	// must not decrypt to the bytes read before the failure.
	if _, err := Decrypt(io.Discard, bytes.NewReader(out.Bytes()), identitiesOf(id)); err == nil {
		t.Fatal("an abandoned encryption decrypted cleanly")
	}
}

// TestEncryptStreamsBeforeEOF: with plaintext arriving through a pipe,
// ciphertext is out while the producer is still paused mid-input.  A
// whole-buffer design could not produce a byte before the input ended.
func TestEncryptStreamsBeforeEOF(t *testing.T) {
	id := testKey(t)
	const before, after = 4 * 64 << 10, 100
	plainIn, intoEncrypt := io.Pipe()
	cipher := &signalWriter{payload: make(chan struct{})}

	var source *genStream
	release := make(chan struct{})
	producerPaused := make(chan struct{})
	var finished atomic.Bool
	go func() { // the producer: data, a pause, the rest
		source = newGenStream(before, nil)
		if _, err := io.Copy(intoEncrypt, source); err != nil {
			t.Error(err)
		}
		close(producerPaused)
		<-release
		source.left = after // more bytes of the same stream, on release
		if _, err := io.Copy(intoEncrypt, source); err != nil {
			t.Error(err)
		}
		intoEncrypt.Close()
		finished.Store(true)
	}()

	done := make(chan error, 1)
	go func() { done <- Encrypt(cipher, plainIn, recipientsOf(id)) }()

	select {
	case <-cipher.payload:
	case <-time.After(10 * time.Second):
		t.Fatal("no ciphertext before the input reached EOF")
	}
	<-producerPaused
	if finished.Load() {
		t.Fatal("the input finished before the ciphertext was checked; the proof is void")
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("encryption did not finish")
	}

	want := source.sum.Sum(nil)
	got := sha256.Sum256(decryptBytes(t, cipher.bytes(), identitiesOf(id)))
	if !bytes.Equal(got[:], want) || source.left != 0 || int64(len(cipher.bytes())) <= 4096 {
		t.Fatalf("round trip of the piped stream differs from its source")
	}
}

// signalWriter keeps what it is given and closes payload once more
// than a header's worth of bytes — an encrypted chunk — has arrived.
type signalWriter struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	payload chan struct{}
	once    sync.Once
}

func (w *signalWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Write(p)
	if w.buf.Len() > 4096 {
		w.once.Do(func() { close(w.payload) })
	}
	return len(p), nil
}

func (w *signalWriter) bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return bytes.Clone(w.buf.Bytes())
}

// lagTracker wraps a stage's source and its destination to measure
// how far the stage reads ahead of what it has written out.  A
// streaming stage stays within a chunk or two; one that gathers the
// whole payload reads everything first.  (Ciphertext runs slightly
// longer than plaintext, so "ahead" is if anything understated.)
type lagTracker struct {
	read, written int64
	lag           int64 // the most read-but-not-yet-written
}

func (l *lagTracker) note() {
	if lag := l.read - l.written; lag > l.lag {
		l.lag = lag
	}
}

// src and dst wrap a stage's input and output.
func (l *lagTracker) src(r io.Reader) io.Reader { return &lagReader{l: l, r: r} }
func (l *lagTracker) dst(w io.Writer) io.Writer { return &lagWriter{l: l, w: w} }

type lagReader struct {
	l *lagTracker
	r io.Reader
}

func (x *lagReader) Read(p []byte) (int, error) {
	n, err := x.r.Read(p)
	x.l.read += int64(n)
	x.l.note()
	return n, err
}

type lagWriter struct {
	l *lagTracker
	w io.Writer
}

func (x *lagWriter) Write(p []byte) (int, error) {
	n, err := x.w.Write(p)
	x.l.written += int64(n)
	return n, err
}

// TestMultiChunkStreamThroughFiles: a generated multi-chunk stream is
// encrypted to a file and decrypted from it into a digest.  Neither
// direction ever reads more than two chunks ahead of what it has
// written — the payload is never gathered — and the digest and length
// come out as the generator's own.
func TestMultiChunkStreamThroughFiles(t *testing.T) {
	id := testKey(t)
	const size = int64(12)<<20 + 100_003
	src := newGenStream(size, nil)

	dir := t.TempDir()
	cipherPath := filepath.Join(dir, "stream.age")
	f, err := os.Create(cipherPath)
	if err != nil {
		t.Fatal(err)
	}
	encrypting := &lagTracker{}
	if err := Encrypt(encrypting.dst(&sizedWriter{w: f}), encrypting.src(src), recipientsOf(id)); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	in, err := os.Open(cipherPath)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	decrypting := &lagTracker{}
	toDigest := &sizedWriter{w: sha256.New()}
	n, err := Decrypt(decrypting.dst(toDigest), decrypting.src(in), identitiesOf(id))
	if err != nil {
		t.Fatal(err)
	}
	got := hex.EncodeToString(toDigest.w.(hash.Hash).Sum(nil))
	if want := hex.EncodeToString(src.sum.Sum(nil)); got != want || n != size || src.left != 0 {
		t.Fatalf("digest or length differs: %d of %d bytes, %s vs %s", n, size, got, want)
	}

	// io.Copy hands over 32 KiB at a time and a chunk is 64 KiB, so a
	// streaming stage is at most two chunks ahead — never the payload.
	for _, stage := range []struct {
		name string
		l    *lagTracker
	}{{"encryption", encrypting}, {"decryption", decrypting}} {
		if stage.l.lag > 2*ChunkSize {
			t.Errorf("%s read %d bytes ahead of its output: the payload was gathered, not streamed",
				stage.name, stage.l.lag)
		}
	}
}
