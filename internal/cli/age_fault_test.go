/*
Copyright (C) Philip Schlump, 2012-2026.

MIT Licensed.
*/

package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pschlump/xtar/internal/ageio"
)

var (
	errDisk   = errors.New("no space left on device")
	errSource = errors.New("source read error")
)

// errReader fails where it stands in for the rest of a stream.
type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

// ageWithStdin replaces the command's standard input for the rest of
// the test.
func ageWithStdin(t *testing.T, open func() ageSource) {
	t.Helper()
	old := ageStdin
	ageStdin = open
	t.Cleanup(func() { ageStdin = old })
}

// faultyStage is a real staged output that fails on cue: once more
// than budget bytes were written, at Commit, or right after it.
type faultyStage struct {
	ageStage
	path        string
	budget      int64
	written     int64 // bytes the stream got through before a failure
	failCommit  bool
	afterCommit error
}

func (s *faultyStage) Write(p []byte) (int, error) {
	if s.budget < int64(len(p)) {
		return 0, errDisk
	}
	n, err := s.ageStage.Write(p)
	s.budget -= int64(n)
	s.written += int64(n)
	return n, err
}

func (s *faultyStage) Commit() error {
	if s.failCommit {
		s.Abort()
		return fmt.Errorf("cannot publish %s: %w", s.path, errDisk)
	}
	if err := s.ageStage.Commit(); err != nil {
		return err
	}
	return s.afterCommit
}

// ageLastFault is the stage the command most recently opened under
// ageFaultyStage, so a test can see how far the stream got.
var ageLastFault *faultyStage

// ageFaultyStage makes every output the command stages for the rest
// of the (sub)test a faultyStage.
func ageFaultyStage(t *testing.T, budget int64, failCommit bool, afterCommit error) {
	t.Helper()
	real := newAgeStage
	newAgeStage = func(path string) (ageStage, error) {
		f, err := real(path)
		if err != nil {
			return nil, err
		}
		ageLastFault = &faultyStage{ageStage: f, path: path, budget: budget,
			failCommit: failCommit, afterCommit: afterCommit}
		return ageLastFault, nil
	}
	t.Cleanup(func() { newAgeStage = real })
}

// ageStaged is the size of the file staged for dest in dir (-1 when
// there is none).
func ageStaged(dir, dest string) int64 {
	des, _ := os.ReadDir(dir)
	for _, de := range des {
		if strings.HasPrefix(de.Name(), "."+filepath.Base(dest)+".tmp-") {
			if fi, err := de.Info(); err == nil {
				return fi.Size()
			}
		}
	}
	return -1
}

// TestAgeFailClosed: a wrong key, a file no key of ours opens, and
// every kind of damage to an age file end in exit 2 with no
// destination and no staged file left behind.
func TestAgeFailClosed(t *testing.T) {
	identity, recipients, _ := ageKeys(t)
	wrong, _, _ := ageKeys(t)
	dir := t.TempDir()
	const chunk = ageio.ChunkSize
	plain := agePlain(3*chunk + 7)
	_, cipher, errs := ageCall(bytes.NewReader(plain), "age-encrypt", "-R", recipients)
	if len(errs) != 0 {
		t.Fatalf("setup: %s", errs)
	}

	// Layout: header lines, the 16-byte nonce, three full chunks, a
	// last one of 7 bytes.
	mac := bytes.Index(cipher, []byte("\n--- "))
	body := mac + 1 + bytes.IndexByte(cipher[mac+1:], '\n') + 1
	const enc = chunk + 16
	secondChunk := body + 16 + enc
	flip := func(b []byte, i int) []byte {
		out := bytes.Clone(b)
		if out[i] == 'A' {
			out[i] = 'B'
		} else {
			out[i] = 'A'
		}
		return out
	}
	damaged := filepath.Join(dir, "damaged.age")
	out := filepath.Join(dir, "restored")

	refuse := func(name string, run func() (int, []byte, []byte), want string) {
		t.Helper()
		code, stdout, errs := run()
		if code != exitFatal || len(stdout) != 0 {
			t.Errorf("%s: exit %d, %d bytes on stdout, err %q", name, code, len(stdout), errs)
		}
		if want != "" && !strings.Contains(string(errs), want) {
			t.Errorf("%s: err %q lacks %q", name, errs, want)
		}
		if _, err := os.Lstat(out); !os.IsNotExist(err) {
			t.Errorf("%s: a destination was published: %v", name, err)
		}
		ageOnly(t, dir, "damaged.age")
	}

	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"empty file", nil},
		{"not age", append([]byte{0x1f, 0x8b, 0x08, 0}, bytes.Repeat([]byte{7}, 500)...)},
		{"truncated header", cipher[:20]},
		{"header without MAC", cipher[:mac]},
		{"modified header MAC", flip(cipher, mac+20)},
		{"header only", cipher[:body]},
		{"modified nonce", flip(cipher, body+3)},
		{"modified first chunk", flip(cipher, body+500)},
		{"modified middle chunk", flip(cipher, secondChunk+500)},
		{"modified final chunk", flip(cipher, len(cipher)-1)},
		{"truncated final chunk", cipher[:len(cipher)-1]},
		{"truncated mid-chunk", cipher[:secondChunk+300]},
		{"truncated at chunk boundary", cipher[:secondChunk]},
		{"trailing data", append(bytes.Clone(cipher), "garbage"...)},
	} {
		if err := os.WriteFile(damaged, tc.data, 0o600); err != nil {
			t.Fatal(err)
		}
		refuse(tc.name, func() (int, []byte, []byte) {
			return ageCall(nil, "age-decrypt", "-i", identity, "-o", out, damaged)
		}, "")
		// From standard input the same file fails the same way.
		refuse(tc.name+" (stdin)", func() (int, []byte, []byte) {
			return ageCall(bytes.NewReader(tc.data), "age-decrypt", "-i", identity, "-o", out)
		}, "")
	}

	if err := os.WriteFile(damaged, cipher, 0o600); err != nil {
		t.Fatal(err)
	}
	refuse("wrong identity", func() (int, []byte, []byte) {
		return ageCall(nil, "age-decrypt", "-i", wrong, "-o", out, damaged)
	}, "no identity matched")
	refuse("no matching identity", func() (int, []byte, []byte) {
		return ageCall(nil, "age-decrypt", "-i", wrong, "-i", wrong, "-o", out, damaged)
	}, "no identity matched")
	// The right key among others still opens it: the failure above is
	// the key's, not the file's.
	if code, got, errs := ageCall(nil, "age-decrypt", "-i", wrong, "-i", identity, damaged); code != exitOK || !bytes.Equal(got, plain) {
		t.Errorf("the right identity among others: exit %d, %d bytes, %s", code, len(got), errs)
	}
	ageOnly(t, dir, "damaged.age")
}

// TestAgeCorruptFinalChunkNeverPublished: the final chunk of an age
// file authenticates only when it is read, so by then the plaintext
// before it has been decrypted and written to the staged file.  This
// feeds a damaged file a chunk at a time and looks at the directory
// between chunks: the staged file grows, the destination never
// appears, and at the failure the staged file is gone.
func TestAgeCorruptFinalChunkNeverPublished(t *testing.T) {
	identity, recipients, _ := ageKeys(t)
	dir := t.TempDir()
	const chunk = ageio.ChunkSize
	plain := agePlain(3*chunk + 7)
	_, intact, _ := ageCall(bytes.NewReader(plain), "age-encrypt", "-R", recipients)
	mac := bytes.Index(intact, []byte("\n--- "))
	body := mac + 1 + bytes.IndexByte(intact[mac+1:], '\n') + 1
	const enc = chunk + 16

	spoiled := func(c []byte) []byte {
		c = bytes.Clone(c)
		c[len(c)-3] ^= 0x40
		return c
	}
	for _, tc := range []struct {
		name   string
		cipher []byte
	}{
		{"modified final chunk", spoiled(intact)},
		{"truncated final chunk", bytes.Clone(intact[:len(intact)-1])},
	} {
		out := filepath.Join(dir, "restored")

		// To standard output the prefix does come out, and is said to.
		code, stdout, errs := ageCall(bytes.NewReader(tc.cipher), "age-decrypt", "-i", identity)
		if code != exitFatal || !bytes.Equal(stdout, plain[:3*chunk]) {
			t.Errorf("%s → stdout: exit %d, %d bytes, err %q", tc.name, code, len(stdout), errs)
		}
		if !strings.Contains(string(errs), "standard output") || !strings.Contains(string(errs), "incomplete") {
			t.Errorf("%s → stdout: the partial output was not flagged: %q", tc.name, errs)
		}

		// To a file: header, nonce and the first chunk, then one chunk
		// per write, each followed by a look at the directory.
		unhooked := ageStdin
		pr, pw := io.Pipe()
		ageWithStdin(t, func() ageSource { return ageSource{Reader: pr, name: "standard input"} })
		payload := body + 16 // the nonce precedes the chunks
		pieces := [][]byte{
			tc.cipher[:payload+enc],
			tc.cipher[payload+enc : payload+2*enc],
			tc.cipher[payload+2*enc : payload+3*enc],
			tc.cipher[payload+3*enc:],
		}
		var staging error
		var staged []int64
		fed := make(chan struct{})
		go func() {
			defer close(fed)
			defer pw.Close() // on every path: never leave the command waiting
			for i, piece := range pieces {
				if _, err := pw.Write(piece); err != nil {
					staging = err
					return
				}
				if i == len(pieces)-1 {
					break
				}
				// The staged file must now hold chunk i+1 in the clear.
				if staging = ageWaitStaged(dir, out, int64(i+1)*chunk); staging != nil {
					return
				}
				staged = append(staged, ageStaged(dir, out))
			}
		}()
		code, stdout, errs = ageCall(nil, "age-decrypt", "-i", identity, "-o", out)
		ageStdin = unhooked // this seam is for this run alone
		// A command that gave up without reading (as a broken one might)
		// must not leave the feeder blocked: closing the read end fails
		// its pending write, and the test reports that instead of hanging.
		pr.CloseWithError(errors.New("the command stopped reading its input"))
		<-fed
		if staging != nil {
			t.Errorf("%s → file: %v", tc.name, staging)
		}
		if code != exitFatal || len(stdout) != 0 {
			t.Errorf("%s → file: exit %d, %d bytes on stdout, err %q", tc.name, code, len(stdout), errs)
		}
		if len(staged) != 3 || staged[0] < chunk || staged[1] < 2*chunk || staged[2] < 3*chunk {
			t.Errorf("%s → file: staged sizes %v; the plaintext prefix was not observed in the staged file", tc.name, staged)
		}
		if _, err := os.Lstat(out); !os.IsNotExist(err) {
			t.Errorf("%s → file: the destination was published: %v", tc.name, err)
		}
		ageOnly(t, dir)
	}
}

// ageWaitStaged waits until the file staged for dest in dir holds want
// bytes, failing if dest itself shows up at any point.  It returns in
// microseconds when the command is streaming; the deadline is only for
// one that is not.
func ageWaitStaged(dir, dest string, want int64) error {
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if _, err := os.Lstat(dest); !os.IsNotExist(err) {
			return fmt.Errorf("%s appeared while %d bytes were staged", dest, want)
		}
		if size := ageStaged(dir, dest); size >= want {
			return nil
		}
		time.Sleep(2 * time.Millisecond)
	}
	return fmt.Errorf("the staged file for %s never reached %d bytes", dest, want)
}

// TestAgeSourceReadError: an input that fails mid-stream fails the
// command, is blamed on the input, and publishes nothing.
func TestAgeSourceReadError(t *testing.T) {
	identity, recipients, _ := ageKeys(t)
	dir := t.TempDir()
	plain := agePlain(3*ageio.ChunkSize + 5)
	out := filepath.Join(dir, "out.age")

	for _, cut := range []int{0, 100_000, 2 * ageio.ChunkSize, len(plain)} {
		ageWithStdin(t, func() ageSource {
			return ageSource{Reader: io.MultiReader(bytes.NewReader(plain[:cut]), errReader{err: errSource}), name: "standard input"}
		})
		code, stdout, errs := ageCall(nil, "age-encrypt", "-R", recipients, "-o", out)
		if code != exitFatal || len(stdout) != 0 || !strings.Contains(string(errs), "read standard input: source read error") {
			t.Errorf("cut at %d: exit %d, %d bytes on stdout, err %q", cut, code, len(stdout), errs)
		}
		if _, err := os.Lstat(out); !os.IsNotExist(err) {
			t.Errorf("cut at %d: a destination was published: %v", cut, err)
		}
		ageOnly(t, dir)
	}

	// In a pipeline the partial ciphertext is already downstream; the
	// error says so, and no key can decrypt what came out.
	ageWithStdin(t, func() ageSource {
		return ageSource{Reader: io.MultiReader(bytes.NewReader(plain[:100_000]), errReader{err: errSource}), name: "standard input"}
	})
	code, stdout, errs := ageCall(nil, "age-encrypt", "-R", recipients)
	if code != exitFatal || len(stdout) == 0 || !strings.Contains(string(errs), "standard output") {
		t.Errorf("pipeline: exit %d, %d bytes, err %q", code, len(stdout), errs)
	}
	if code, _, _ := ageCall(bytes.NewReader(stdout), "age-decrypt", "-i", identity); code != exitFatal {
		t.Errorf("an abandoned encryption's output decrypted: exit %d", code)
	}
}

// TestAgeDestinationFaults: when the output itself fails — the first
// write, a write once the stream is under way, or the final publish —
// the command fails, blames the output, and leaves nothing behind.
func TestAgeDestinationFaults(t *testing.T) {
	identity, recipients, _ := ageKeys(t)
	dir := t.TempDir()
	plain := agePlain(3*ageio.ChunkSize + 9)
	src := ageWrite(t, filepath.Join(dir, "wal"), string(plain))
	cipher := filepath.Join(dir, "wal.age")
	if code, _, errs := ageCall(nil, "age-encrypt", "-R", recipients, "-o", cipher, src); code != exitOK {
		t.Fatalf("setup encrypt: exit %d: %s", code, errs)
	}

	for _, verb := range []struct {
		name string
		head []string
	}{
		{"age-encrypt", []string{"age-encrypt", "-R", recipients, "-o", "@", src}},
		{"age-decrypt", []string{"age-decrypt", "-i", identity, "-o", "@", cipher}},
	} {
		for _, fault := range []struct {
			name       string
			budget     int64 // bytes the output accepts before failing
			failCommit bool  // fail the publish instead of a write
			gotThrough int64 // least bytes the stream must have staged
		}{
			{"first write", 0, false, 0},
			{"mid-stream write", 100_000, false, 4096},
			{"publish", 1 << 62, true, int64(len(plain))},
		} {
			t.Run(verb.name+"/"+fault.name, func(t *testing.T) {
				out := filepath.Join(dir, "out")
				ageFaultyStage(t, fault.budget, fault.failCommit, nil)
				args := append([]string{}, verb.head...)
				for i, a := range args {
					if a == "@" {
						args[i] = out
					}
				}
				code, stdout, errs := ageCall(nil, args...)
				if code != exitFatal || len(stdout) != 0 || !strings.Contains(string(errs), verb.name+": ") {
					t.Fatalf("exit %d, %d bytes on stdout, err %q", code, len(stdout), errs)
				}
				if fault.failCommit {
					if !strings.Contains(string(errs), "cannot publish "+out) {
						t.Errorf("err %q does not name the unpublished output", errs)
					}
				} else if !strings.Contains(string(errs), "write "+out+": no space left on device") {
					t.Errorf("err %q does not blame the output", errs)
				}
				if ageLastFault == nil || ageLastFault.written < fault.gotThrough {
					t.Errorf("the stream staged %v bytes; the fault did not land where intended (want at least %d)", ageLastFault, fault.gotThrough)
				}
				if _, err := os.Lstat(out); !os.IsNotExist(err) {
					t.Errorf("a destination was published: %v", err)
				}
				ageOnly(t, dir, "wal", "wal.age")
			})
		}
	}
}

// TestAgePublishedIsSuccessWithWarning: when the output is in place and
// only its directory would not sync, the command completes with a
// warning — exit 1, the repository's "completed with warnings" — and
// the file is intact.
func TestAgePublishedIsSuccessWithWarning(t *testing.T) {
	identity, recipients, _ := ageKeys(t)
	dir := t.TempDir()
	plain := agePlain(70_000)
	out := filepath.Join(dir, "out.age")
	ageFaultyStage(t, 1<<62, false, &ageio.PublishedError{Path: out,
		Err: errors.New("its directory was not synced: input/output error")})

	code, stdout, errs := ageCall(bytes.NewReader(plain), "age-encrypt", "-R", recipients, "-o", out)
	if code != exitWarn || len(stdout) != 0 || !strings.HasPrefix(string(errs), "xtar: age-encrypt: ") || !strings.Contains(string(errs), "was published") {
		t.Errorf("exit %d, stdout %q, err %q", code, stdout, errs)
	}
	if fi, err := os.Stat(out); err != nil || fi.Size() < int64(len(plain)) || fi.Mode().Perm() != 0o600 {
		t.Errorf("the published output is missing or wrong: %v", err)
	}
	// It is a complete file: it decrypts.
	if code, got, errs := ageCall(nil, "age-decrypt", "-i", identity, out); code != exitOK || !bytes.Equal(got, plain) {
		t.Errorf("the published output does not decrypt: exit %d, %s", code, errs)
	}
	ageOnly(t, dir, "out.age")
}
