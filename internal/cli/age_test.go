/*
Copyright (C) Philip Schlump, 2012-2026.

MIT Licensed.
*/

package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/pschlump/xtar/internal/ageio"
)

// ageCall runs `xtar ARGS...` with in as standard input (closed and
// empty when nil) and returns its exit code and both output streams.
// The streams drain while the command runs, so a pipeline of any size
// cannot block.
func ageCall(in io.Reader, args ...string) (code int, stdout, stderr []byte) {
	var out bytes.Buffer
	code, stderr = ageRun(in, &out, args...)
	return code, out.Bytes(), stderr
}

// ageRun is ageCall with standard output streamed to sink, for output
// too large to keep.  It returns the exit code and standard error.
func ageRun(in io.Reader, sink io.Writer, args ...string) (code int, stderr []byte) {
	inR, inW, err := os.Pipe()
	if err != nil {
		panic(err)
	}
	outR, outW, _ := os.Pipe()
	errR, errW, _ := os.Pipe()

	oldIn, oldOut, oldErr := os.Stdin, os.Stdout, os.Stderr
	os.Stdin, os.Stdout, os.Stderr = inR, outW, errW

	var errBuf bytes.Buffer
	var drained sync.WaitGroup
	drained.Add(2)
	go func() { defer drained.Done(); _, _ = io.Copy(sink, outR) }()
	go func() { defer drained.Done(); _, _ = io.Copy(&errBuf, errR) }()
	fed := make(chan struct{})
	go func() {
		defer close(fed)
		if in != nil {
			_, _ = io.Copy(inW, in)
		}
		inW.Close()
	}()

	code = Xtar("xtar", args)

	os.Stdin, os.Stdout, os.Stderr = oldIn, oldOut, oldErr
	outW.Close()
	errW.Close()
	inR.Close() // a command that left input unread unblocks the feeder
	drained.Wait()
	<-fed
	return code, errBuf.Bytes()
}

// ageKeys generates a fresh key pair through the command under test,
// in a directory only this test sees.  It returns the identity path,
// the recipients path, and the recipient.
func ageKeys(t *testing.T) (identity, recipients, recipient string) {
	t.Helper()
	dir := t.TempDir()
	identity = filepath.Join(dir, "identity.txt")
	recipients = filepath.Join(dir, "recipients.txt")
	code, out, errs := ageCall(nil, "age-keygen", "--identity-output", identity, "--recipient-output", recipients)
	if code != exitOK {
		t.Fatalf("age-keygen exit %d: %s", code, errs)
	}
	return identity, recipients, strings.TrimSpace(string(out))
}

// ageSecret reads the test's own identity file so further key files
// can be built from it.  Nothing prints it, and the tests check that
// the command never does either.
func ageSecret(t *testing.T, identity string) string {
	t.Helper()
	data, err := os.ReadFile(identity)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// ageEntries lists a directory, dotfiles included.
func ageEntries(t *testing.T, dir string) []string {
	t.Helper()
	des, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, de := range des {
		names = append(names, de.Name())
	}
	return names
}

// ageOnly fails if dir holds anything besides want.
func ageOnly(t *testing.T, dir string, want ...string) {
	t.Helper()
	have := map[string]bool{}
	for _, name := range ageEntries(t, dir) {
		have[name] = true
	}
	for _, name := range want {
		delete(have, name)
	}
	if len(have) != 0 {
		t.Errorf("unexpected files left in %s: %v", dir, have)
	}
}

func ageWrite(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// ageMode is a file's permission bits.
func ageMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

// ageGen is a deterministic, incompressible stream of splitmix64 words
// — WAL pages and base-backup blocks in a test.  It keeps nothing: each
// Read fills the caller's buffer and feeds the same bytes to sum, so
// the digest of a stream far larger than memory is known without
// holding any of it.  sample runs every 2 MiB.
type ageGen struct {
	state  uint64
	left   int64
	sum    hash.Hash
	reads  int
	sample func()
}

func newAgeGen(n int64, sample func()) *ageGen {
	return &ageGen{state: 0x243F6A8885A308D3, left: n, sum: sha256.New(), sample: sample}
}

func (g *ageGen) Read(p []byte) (int, error) {
	if g.left <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > g.left {
		p = p[:g.left]
	}
	var word [8]byte
	for i := 0; i < len(p); i += 8 {
		g.state += 0x9E3779B97F4A7C15
		z := g.state
		z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
		z = (z ^ (z >> 27)) * 0x94D049BB133111EB
		binary.LittleEndian.PutUint64(word[:], z^(z>>31))
		copy(p[i:], word[:])
	}
	g.left -= int64(len(p))
	g.sum.Write(p)
	if g.reads++; g.sample != nil && g.reads%64 == 0 {
		g.sample()
	}
	return len(p), nil
}

// agePlain is the first n bytes of the stream, as a buffer.
func agePlain(n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(newAgeGen(int64(n), nil), b); err != nil {
		panic(err)
	}
	return b
}

// TestAgeKeygen: a fresh, parseable X25519 identity and its recipient,
// private by mode, with the private key on neither output stream.
func TestAgeKeygen(t *testing.T) {
	old := syscall.Umask(0o077) // would narrow the public file
	defer syscall.Umask(old)
	dir := t.TempDir()
	identity := filepath.Join(dir, "backup-age-identity.txt")
	recipients := filepath.Join(dir, "backup-age-recipients.txt")

	code, out, errs := ageCall(nil, "age-keygen", "--identity-output", identity, "--recipient-output", recipients)
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if recipient := string(out); strings.Count(recipient, "\n") != 1 || !strings.HasPrefix(recipient, "age1") {
		t.Errorf("standard output is %q, want the single recipient and a newline", out)
	}
	recipient := strings.TrimSpace(string(out))
	if got, err := os.ReadFile(recipients); err != nil || string(got) != recipient+"\n" {
		t.Errorf("recipients file %q, %v", got, err)
	}
	if mode := ageMode(t, identity); mode != 0o600 {
		t.Errorf("identity file mode %o, want 600", mode)
	}
	if mode := ageMode(t, recipients); mode != 0o644 {
		t.Errorf("recipients file mode %o, want 644 under umask 077", mode)
	}
	secret := ageSecret(t, identity)
	if !strings.Contains(secret, "\nAGE-SECRET-KEY-1") || !strings.Contains(secret, "# public key: "+recipient) {
		t.Error("the identity file is not the standard age-keygen form")
	}
	for name, stream := range map[string][]byte{"stdout": out, "stderr": errs} {
		for _, line := range strings.Split(secret, "\n") {
			if strings.HasPrefix(line, "AGE-SECRET-KEY-1") && bytes.Contains(stream, []byte(line)) {
				t.Errorf("the private identity was printed on %s", name)
			}
		}
	}
	ageOnly(t, dir, "backup-age-identity.txt", "backup-age-recipients.txt")

	// The pair works, and a second run is a different key.
	plain := ageWrite(t, filepath.Join(dir, "a"), "it works\n")
	if code, _, errs := ageCall(nil, "age-encrypt", "-R", recipients, "-o", filepath.Join(dir, "a.age"), plain); code != exitOK {
		t.Fatalf("encrypt with the new pair: exit %d: %s", code, errs)
	}
	if code, out, errs := ageCall(nil, "age-decrypt", "-i", identity, filepath.Join(dir, "a.age")); code != exitOK || string(out) != "it works\n" {
		t.Errorf("decrypt with the new pair: exit %d, %q, %s", code, out, errs)
	}
	if _, out, _ := ageCall(nil, "age-keygen", "--identity-output", filepath.Join(dir, "i2"), "--recipient-output", filepath.Join(dir, "r2")); strings.TrimSpace(string(out)) == recipient {
		t.Error("the second key pair repeated the first recipient")
	}
}

// TestAgeKeygenRefuses: neither output file is ever replaced, and a
// refused run leaves what was there — and nothing else.
func TestAgeKeygenRefuses(t *testing.T) {
	dir := t.TempDir()
	identity, recipients := filepath.Join(dir, "identity.txt"), filepath.Join(dir, "recipients.txt")

	ageWrite(t, recipients, "age1old-recipients-placeholder\n")
	code, out, errs := ageCall(nil, "age-keygen", "--identity-output", identity, "--recipient-output", recipients)
	if code != exitFatal || len(out) != 0 || !strings.HasPrefix(string(errs), "xtar: age-keygen: ") || !strings.Contains(string(errs), "already exists") {
		t.Errorf("existing recipients: exit %d, out %q, err %q", code, out, errs)
	}
	ageOnly(t, dir, "recipients.txt")
	if got, _ := os.ReadFile(recipients); string(got) != "age1old-recipients-placeholder\n" {
		t.Errorf("the existing recipients file was modified: %q", got)
	}

	ageWrite(t, identity, "AGE-SECRET-KEY-1old-identity-placeholder\n")
	code, out, errs = ageCall(nil, "age-keygen", "--identity-output", identity, "--recipient-output", filepath.Join(dir, "new-recipients"))
	if code != exitFatal || len(out) != 0 || !strings.Contains(string(errs), "already exists") {
		t.Errorf("existing identity: exit %d, out %q, err %q", code, out, errs)
	}
	if _, err := os.Lstat(filepath.Join(dir, "new-recipients")); !os.IsNotExist(err) {
		t.Errorf("a recipients file was published beside a refused identity: %v", err)
	}
	ageOnly(t, dir, "identity.txt", "recipients.txt")
	if got, _ := os.ReadFile(identity); string(got) != "AGE-SECRET-KEY-1old-identity-placeholder\n" {
		t.Errorf("the existing identity file was modified: %q", got)
	}

	// One path for both: the private key would land in the public file.
	code, _, errs = ageCall(nil, "age-keygen", "--identity-output", filepath.Join(dir, "same"), "--recipient-output", filepath.Join(dir, "./same"))
	if code != exitFatal || !strings.Contains(string(errs), "two different files") {
		t.Errorf("same path twice: exit %d, err %q", code, errs)
	}
	ageOnly(t, dir, "identity.txt", "recipients.txt")
}

// TestAgeKeygenArgErrors: missing, empty, repeated, unknown, or extra
// arguments are exit 2, with nothing written.
func TestAgeKeygenArgErrors(t *testing.T) {
	dir := t.TempDir()
	identity, recipients := filepath.Join(dir, "identity.txt"), filepath.Join(dir, "recipients.txt")
	for name, args := range map[string][]string{
		"no flags":        {},
		"identity only":   {"--identity-output", identity},
		"recipient only":  {"--recipient-output", recipients},
		"empty identity":  {"--identity-output", "", "--recipient-output", recipients},
		"empty recipient": {"--identity-output", identity, "--recipient-output", ""},
		"unknown flag":    {"--identity-output", identity, "--recipient-output", recipients, "--force"},
		"short alias":     {"-i", identity, "-r", recipients},
		"operand":         {"--identity-output", identity, "--recipient-output", recipients, "extra"},
		"repeated":        {"--identity-output", identity, "--identity-output", identity, "--recipient-output", recipients},
		"missing value":   {"--identity-output", identity, "--recipient-output"},
	} {
		code, out, errs := ageCall(nil, append([]string{"age-keygen"}, args...)...)
		if code != exitFatal || len(out) != 0 || !strings.HasPrefix(string(errs), "xtar: age-keygen: ") {
			t.Errorf("%s: exit %d, out %q, err %q", name, code, out, errs)
		}
	}
	ageOnly(t, dir)
}

// TestAgeRoundTrip: every input/output spelling — file to file, stdin
// to file, file to stdout, stdin to stdout, the long, short, and
// attached flags — carries a payload through unchanged.
func TestAgeRoundTrip(t *testing.T) {
	identity, recipients, _ := ageKeys(t)
	dir := t.TempDir()
	t.Chdir(dir) // relative names: the staged file must land beside its destination
	plain := agePlain(200_003)
	ageWrite(t, "base.tar.gz", string(plain))

	run := func(in io.Reader, args ...string) []byte {
		t.Helper()
		code, out, errs := ageCall(in, args...)
		if code != exitOK {
			t.Fatalf("%v: exit %d: %s", args, code, errs)
		}
		if len(errs) != 0 {
			t.Errorf("%v: a clean run printed %q", args, errs)
		}
		return out
	}
	same := func(got []byte, what string) {
		t.Helper()
		if !bytes.Equal(got, plain) {
			t.Errorf("%s: %d bytes back, differs from the source", what, len(got))
		}
	}

	// file → file
	run(nil, "age-encrypt", "-R", recipients, "-o", "base.tar.gz.age", "base.tar.gz")
	if mode := ageMode(t, "base.tar.gz.age"); mode != 0o600 {
		t.Errorf("ciphertext mode %o, want 600", mode)
	}
	run(nil, "age-decrypt", "-i", identity, "-o", "restored.tar.gz", "base.tar.gz.age")
	got, _ := os.ReadFile("restored.tar.gz")
	same(got, "file → file")
	if mode := ageMode(t, "restored.tar.gz"); mode != 0o600 {
		t.Errorf("plaintext mode %o, want 600", mode)
	}

	// stdin → file with the long spellings, then file → stdout both ways
	run(bytes.NewReader(plain), "age-encrypt", "--recipient-file", recipients, "--output", "from-stdin.age")
	same(run(nil, "age-decrypt", "--identity-file", identity, "from-stdin.age"), "file → stdout")
	same(run(nil, "age-decrypt", "--identity-file", identity, "-o", "-", "from-stdin.age"), "file → -o -")

	// file → stdout, implicit and with the attached spellings
	cipher := run(nil, "age-encrypt", "--recipient-file="+recipients, "base.tar.gz")
	run(nil, "age-encrypt", "-R"+recipients, "--output=-", "base.tar.gz")

	// stdin → stdout, "-" named on both sides
	same(run(bytes.NewReader(cipher), "age-decrypt", "-i", identity, "-"), "stdin → stdout")
	run(bytes.NewReader(plain), "age-encrypt", "-R", recipients, "-o", "-", "-")
	run(bytes.NewReader(cipher), "age-decrypt", "-i"+identity, "-oout", "-")
	if got, _ := os.ReadFile("out"); !bytes.Equal(got, plain) {
		same(got, "-iFILE -oOUT attached")
	}
	ageOnly(t, dir, "base.tar.gz", "base.tar.gz.age", "restored.tar.gz", "from-stdin.age", "out")
}

// TestAgeSizes: empty, one byte, both sides of the chunk boundaries,
// and several MiB round-trip through the commands byte for byte.
func TestAgeSizes(t *testing.T) {
	identity, recipients, _ := ageKeys(t)
	dir := t.TempDir()
	const chunk = ageio.ChunkSize
	for _, size := range []int{0, 1, 2, chunk - 1, chunk, chunk + 1, 2 * chunk, 2*chunk + 1, 3*chunk + 7, 5<<20 + 1} {
		plain := filepath.Join(dir, "000000010000000000000042")
		cipher, back := plain+".age", filepath.Join(dir, "back")
		ageWrite(t, plain, string(agePlain(size)))
		for _, p := range []string{cipher, back} {
			os.Remove(p)
		}
		if code, _, errs := ageCall(nil, "age-encrypt", "-R", recipients, "-o", cipher, plain); code != exitOK {
			t.Fatalf("size %d encrypt: exit %d: %s", size, code, errs)
		}
		if code, _, errs := ageCall(nil, "age-decrypt", "-i", identity, "-o", back, cipher); code != exitOK {
			t.Fatalf("size %d decrypt: exit %d: %s", size, code, errs)
		}
		if got, _ := os.ReadFile(back); len(got) != size || !bytes.Equal(got, agePlain(size)) {
			t.Errorf("size %d: %d bytes back, differs from the source", size, len(got))
		}
		// The empty input is a complete age file, not an empty one.
		if size == 0 {
			if fi, err := os.Stat(cipher); err != nil || fi.Size() < 150 {
				t.Errorf("the empty input produced a %v-byte ciphertext", fi)
			}
		}
	}
	ageOnly(t, dir, "000000010000000000000042", "000000010000000000000042.age", "back")
}

// TestAgeCiphertextShape: the output is a binary age v1 file — the
// intro and the X25519 stanza in the clear, the plaintext nowhere —
// not armor, gzip, a tar, or a zip.
func TestAgeCiphertextShape(t *testing.T) {
	_, recipients, _ := ageKeys(t)
	dir := t.TempDir()
	secret := "PGDMPwalsegment-secret-payload-0123456789"
	_, cipher, _ := ageCall(nil, "age-encrypt", "-R", recipients, "-o", "-", ageWrite(t, filepath.Join(dir, "wal"), secret))
	if !bytes.HasPrefix(cipher, []byte("age-encryption.org/v1\n")) || !bytes.Contains(cipher, []byte("\n-> X25519 ")) {
		t.Errorf("not a binary age v1 file: %q", cipher[:min(len(cipher), 60)])
	}
	if bytes.Contains(cipher, []byte(secret)) {
		t.Error("the plaintext is visible in the ciphertext")
	}
	for _, alien := range [][]byte{[]byte("-----BEGIN"), {0x1f, 0x8b}, []byte("PK\x03\x04"), []byte("7z\xbc\xaf")} {
		if bytes.HasPrefix(cipher, alien) {
			t.Errorf("ciphertext starts like another format: %x", alien)
		}
	}
}

// TestAgeManyKeys: two -R files encrypt to both recipients, either
// identity opens the file alone, and after a rotation an identity that
// exists only in the second -i file opens what was encrypted to it.
func TestAgeManyKeys(t *testing.T) {
	identityA, recipientsA, recA := ageKeys(t)
	identityB, recipientsB, recB := ageKeys(t)
	dir := t.TempDir()
	plain := ageWrite(t, filepath.Join(dir, "wal"), "segment\n")

	// One file with comments and blank lines holding both keys, or two.
	both := ageWrite(t, filepath.Join(dir, "both.txt"), "# backup host\n\n"+recA+"\n"+recB+"\n\n")
	for name, keys := range map[string][]string{"one file": {"-R", both}, "two files": {"-R", recipientsA, "-R", recipientsB}} {
		cipher := filepath.Join(dir, name+".age")
		args := append([]string{"age-encrypt", "-o", cipher}, keys...)
		if code, _, errs := ageCall(nil, append(args, plain)...); code != exitOK {
			t.Fatalf("%s: encrypt exit %d: %s", name, code, errs)
		}
		for _, who := range []struct{ name, identity string }{{"A", identityA}, {"B", identityB}} {
			if code, out, errs := ageCall(nil, "age-decrypt", "-i", who.identity, cipher); code != exitOK || string(out) != "segment\n" {
				t.Errorf("%s: identity %s alone: exit %d, %q, %s", name, who.name, code, out, errs)
			}
		}
	}

	// Rotation: the retired key's file first, the new key's second.
	retired := ageWrite(t, filepath.Join(dir, "retired.txt"), ageSecret(t, identityA))
	current := ageWrite(t, filepath.Join(dir, "current.txt"), ageSecret(t, identityB))
	rotated := filepath.Join(dir, "rotated.age")
	if code, _, errs := ageCall(nil, "age-encrypt", "-R", recipientsB, "-o", rotated, plain); code != exitOK {
		t.Fatalf("encrypt to the successor: exit %d: %s", code, errs)
	}
	for name, keys := range map[string][]string{"old then new": {"-i", retired, "-i", current}, "new then old": {"-i", current, "-i", retired}} {
		args := append([]string{"age-decrypt"}, keys...)
		if code, out, errs := ageCall(nil, append(args, rotated)...); code != exitOK || string(out) != "segment\n" {
			t.Errorf("identity files %s: exit %d, %q, %s", name, code, out, errs)
		}
	}
	if code, _, errs := ageCall(nil, "age-decrypt", "-i", retired, rotated); code != exitFatal || !strings.Contains(string(errs), "no identity matched") {
		t.Errorf("the retired key alone opened a file encrypted to its successor: exit %d: %s", code, errs)
	}
}
