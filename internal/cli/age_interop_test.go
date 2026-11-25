/*
Copyright (C) Philip Schlump, 2012-2026.

MIT Licensed.
*/

package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pschlump/xtar/internal/ageio"
)

// heapPeak is the largest Go heap its samples have seen.
type heapPeak struct{ peak atomic.Uint64 }

func (h *heapPeak) sample() {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	for {
		p := h.peak.Load()
		if ms.HeapAlloc <= p || h.peak.CompareAndSwap(p, ms.HeapAlloc) {
			return
		}
	}
}

// digestSink hashes what passes through and samples the heap every
// 2 MiB.  It keeps nothing.
type digestSink struct {
	h    hash.Hash
	n    int64
	peak *heapPeak
}

func (s *digestSink) Write(p []byte) (int, error) {
	s.h.Write(p)
	if (s.n / (2 << 20)) != (s.n+int64(len(p)))/(2<<20) {
		s.peak.sample()
	}
	s.n += int64(len(p))
	return len(p), nil
}

// TestAgeLargeStream (opt-in: XTAR_TEST_LARGE=1) pushes 256 MiB
// through the real commands: generated on the fly into age-encrypt's
// standard input, written as a file, then read back by age-decrypt
// into a digest.  The Go heap is sampled throughout.  A round trip of
// whole buffers would show two 256 MiB allocations; streaming shows
// chunk-sized ones only.
func TestAgeLargeStream(t *testing.T) {
	if os.Getenv("XTAR_TEST_LARGE") == "" {
		t.Skip("set XTAR_TEST_LARGE=1 to stream 256 MiB (about that much temporary disk)")
	}
	const size = 256 << 20
	identity, recipients, _ := ageKeys(t)
	dir := t.TempDir()
	cipher := filepath.Join(dir, "base.tar.gz.age")

	peak := &heapPeak{}
	runtime.GC()
	peak.sample()
	base := peak.peak.Load()

	start := time.Now()
	src := newAgeGen(size, peak.sample)
	if code, _, errs := ageCall(src, "age-encrypt", "-R", recipients, "-o", cipher); code != exitOK {
		t.Fatalf("encrypt: exit %d: %s", code, errs)
	}
	encrypting := time.Since(start)

	want := hex.EncodeToString(src.sum.Sum(nil))
	sink := &digestSink{h: sha256.New(), peak: peak}
	start = time.Now()
	if code, errs := ageRun(nil, sink, "age-decrypt", "-i", identity, cipher); code != exitOK {
		t.Fatalf("decrypt: exit %d: %s", code, errs)
	}
	got := hex.EncodeToString(sink.h.Sum(nil))

	if sink.n != size || src.left != 0 {
		t.Errorf("%d of %d bytes came back", sink.n, size)
	}
	if got != want {
		t.Error("the decrypted digest differs from the generated stream's")
	}
	if fi, err := os.Stat(cipher); err != nil || fi.Size() < size || fi.Mode().Perm() != 0o600 {
		t.Errorf("ciphertext file: %v", err)
	}
	// 64 MiB is a fourth of the payload and hundreds of chunk buffers.
	if used := peak.peak.Load() - base; used > 64<<20 {
		t.Errorf("the heap peaked %d MiB over its base: the payload was held, not streamed", used>>20)
	}
	ageOnly(t, dir, "base.tar.gz.age")
	t.Logf("256 MiB encrypted in %s, decrypted in %s; heap peaked %d MiB above its %d MiB base",
		encrypting, time.Since(start), (peak.peak.Load()-base)>>20, base>>20)
}

// TestAgeSystemInterop: against the system age or rage when one is
// installed.  It reads our key files and our ciphertext, we read its
// ciphertext — and, where age-keygen exists, its key files both ways.
// Without either tool the test skips; the rest of the suite does not
// depend on it.
func TestAgeSystemInterop(t *testing.T) {
	bin := ""
	for _, name := range []string{"age", "rage"} {
		if p, err := exec.LookPath(name); err == nil {
			bin = p
			break
		}
	}
	if bin == "" {
		t.Skip("neither age nor rage is installed")
	}
	identity, recipients, recipient := ageKeys(t)
	dir := t.TempDir()
	plain := agePlain(3*ageio.ChunkSize + 11)
	src := ageWrite(t, filepath.Join(dir, "wal"), string(plain))

	system := func(stdin io.Reader, args ...string) []byte {
		t.Helper()
		cmd := exec.Command(bin, args...)
		cmd.Stdin = stdin
		out, err := cmd.Output()
		if err != nil {
			detail := ""
			if ee, ok := err.(*exec.ExitError); ok {
				detail = string(ee.Stderr)
			}
			t.Fatalf("%s %v: %v %s", filepath.Base(bin), args, err, detail)
		}
		return out
	}

	// Ours → theirs: our ciphertext and our identity file.
	ours := filepath.Join(dir, "ours.age")
	if code, _, errs := ageCall(nil, "age-encrypt", "-R", recipients, "-o", ours, src); code != exitOK {
		t.Fatalf("encrypt: exit %d: %s", code, errs)
	}
	if got := system(nil, "-d", "-i", identity, ours); !bytes.Equal(got, plain) {
		t.Errorf("the system tool read %d bytes from our file, not %d", len(got), len(plain))
	}
	piped := ageEncryptBytes(t, recipients, plain)
	if got := system(bytes.NewReader(piped), "-d", "-i", identity); !bytes.Equal(got, plain) {
		t.Error("the system tool cannot decrypt our ciphertext from a pipe")
	}

	// Theirs → ours: encrypted to our recipient, given outright and
	// read from our recipients file by the system tool's own -R.
	for name, args := range map[string][]string{
		"recipient":       {"-r", recipient},
		"recipients file": {"-R", recipients},
	} {
		theirs := filepath.Join(dir, "theirs.age")
		system(nil, append(append([]string{}, args...), "-o", theirs, src)...)
		if code, got, errs := ageCall(nil, "age-decrypt", "-i", identity, theirs); code != exitOK || !bytes.Equal(got, plain) {
			t.Errorf("decrypt a file the system tool encrypted (%s): exit %d, %s", name, code, errs)
		}
		if code, _, errs := ageCall(nil, "age-decrypt", "-i", identity, "-o", filepath.Join(dir, "back"), theirs); code != exitOK {
			t.Errorf("decrypt the system tool's file to a file: exit %d: %s", code, errs)
		}
		if back, _ := os.ReadFile(filepath.Join(dir, "back")); !bytes.Equal(back, plain) {
			t.Errorf("the restored file differs (%s)", name)
		}
		os.Remove(filepath.Join(dir, "back"))
	}
	// Their stdout straight into our stdin.
	theirs := system(nil, "-r", recipient, src)
	if code, got, errs := ageCall(bytes.NewReader(theirs), "age-decrypt", "-i", identity); code != exitOK || !bytes.Equal(got, plain) {
		t.Errorf("pipeline system → xtar: exit %d, %s", code, errs)
	}

	// age-keygen's own key files, both ways.
	keygen, err := exec.LookPath("age-keygen")
	if err != nil {
		t.Logf("age-keygen not installed; its key files are not exercised")
		return
	}
	if out, err := exec.Command(keygen, "-y", identity).Output(); err != nil || strings.TrimSpace(string(out)) != recipient {
		t.Errorf("age-keygen -y does not read our identity file: %v %q", err, out)
	}
	theirIdentity := filepath.Join(dir, "their-identity.txt")
	out, err := exec.Command(keygen, "-o", theirIdentity).CombinedOutput()
	if err != nil {
		t.Fatalf("age-keygen -o: %v", err)
	}
	theirRecipient := ""
	for _, line := range strings.Split(string(out), "\n") {
		if r, ok := strings.CutPrefix(line, "Public key: "); ok && strings.HasPrefix(r, "age1") {
			theirRecipient = strings.TrimSpace(r)
		}
	}
	theirRecipients := ageWrite(t, filepath.Join(dir, "their-recipients.txt"), theirRecipient+"\n")
	if ids, err := ageio.LoadIdentities([]string{theirIdentity}); err != nil || len(ids) != 1 {
		t.Skipf("this age-keygen did not write an X25519 identity we can load (%d bytes of output, %v); its keys are not exercised", len(out), err)
	}
	if recs, err := ageio.LoadRecipients([]string{theirRecipients}); err != nil || len(recs) != 1 || theirRecipient == "" {
		t.Skipf("this age-keygen did not report an X25519 recipient (%v); its keys are not exercised", err)
	}
	forTheirs := filepath.Join(dir, "for-theirs.age")
	if code, _, errs := ageCall(nil, "age-encrypt", "-R", theirRecipients, "-o", forTheirs, src); code != exitOK {
		t.Fatalf("encrypt to age-keygen's recipient: exit %d: %s", code, errs)
	}
	if got := system(nil, "-d", "-i", theirIdentity, forTheirs); !bytes.Equal(got, plain) {
		t.Error("the system tool cannot decrypt what we encrypted to its key")
	}
	byTheirs := system(nil, "-r", theirRecipient, src)
	if code, got, errs := ageCall(bytes.NewReader(byTheirs), "age-decrypt", "-i", theirIdentity); code != exitOK || !bytes.Equal(got, plain) {
		t.Errorf("decrypt with age-keygen's identity file: exit %d, %s", code, errs)
	}
}
