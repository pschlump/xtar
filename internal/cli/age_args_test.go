/*
Copyright (C) Philip Schlump, 2012-2026.

MIT Licensed.
*/

package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAgeArgumentErrors: every misuse of the command line is exit 2,
// prints nothing on standard output, names the verb, and touches no
// output.
func TestAgeArgumentErrors(t *testing.T) {
	identity, recipients, _ := ageKeys(t)
	dir := t.TempDir()
	plain := ageWrite(t, filepath.Join(dir, "plain"), "payload\n")
	out := filepath.Join(dir, "out.age")
	badRecipients := ageWrite(t, filepath.Join(dir, "bad-recipients.txt"), "not a key\n")
	badIdentity := ageWrite(t, filepath.Join(dir, "bad-identity.txt"), "-----BEGIN OPENSSH PRIVATE KEY-----\n")
	emptyKeys := ageWrite(t, filepath.Join(dir, "empty.txt"), "# nothing here\n")
	mistake := ageWrite(t, filepath.Join(dir, "mistake.txt"), ageSecret(t, identity))
	wrongWay := ageWrite(t, filepath.Join(dir, "wrong-way.txt"), "age1not-a-valid-recipient\n")

	cases := map[string][]string{
		// key files
		"no -R":                {"age-encrypt", "-o", out, plain},
		"no -i":                {"age-decrypt", "-o", out, plain},
		"missing recipients":   {"age-encrypt", "-R", filepath.Join(dir, "absent.txt"), "-o", out, plain},
		"missing identity":     {"age-decrypt", "-i", filepath.Join(dir, "absent.txt"), "-o", out, plain},
		"malformed recipients": {"age-encrypt", "-R", badRecipients, "-o", out, plain},
		"malformed identity":   {"age-decrypt", "-i", badIdentity, "-o", out, plain},
		"empty key file":       {"age-encrypt", "-R", emptyKeys, "-o", out, plain},
		"private key as -R":    {"age-encrypt", "-R", mistake, "-o", out, plain},
		"recipient as -i":      {"age-decrypt", "-i", recipients, "-o", out, plain},
		"identity as -R only":  {"age-encrypt", "-R", mistake, "-o", out, plain},
		"good then bad -R":     {"age-encrypt", "-R", recipients, "-R", wrongWay, "-o", out, plain},
		"key file is a dir":    {"age-encrypt", "-R", dir, "-o", out, plain},
		"key file from stdin":  {"age-encrypt", "-R", "-", "-o", out, plain},
		"empty key path":       {"age-encrypt", "-R", "", "-o", out, plain},
		"key option w/o value": {"age-encrypt", "-R"},
		"identity w/o value":   {"age-decrypt", "-o", out, "-i"},
		// output
		"duplicate -o":     {"age-encrypt", "-R", recipients, "-o", out, "-o", out, plain},
		"conflicting -o":   {"age-encrypt", "-R", recipients, "-o", out, "--output", filepath.Join(dir, "other"), plain},
		"empty -o":         {"age-encrypt", "-R", recipients, "-o", "", plain},
		"output w/o value": {"age-encrypt", "-R", recipients, plain, "-o"},
		"output is a dir":  {"age-encrypt", "-R", recipients, "-o", dir, plain},
		"dir is gone":      {"age-encrypt", "-R", recipients, "-o", filepath.Join(dir, "no-such-dir", "x.age"), plain},
		// input
		"two operands":  {"age-encrypt", "-R", recipients, "-o", out, plain, plain},
		"empty operand": {"age-encrypt", "-R", recipients, "-o", out, ""},
		"input is dir":  {"age-encrypt", "-R", recipients, "-o", out, dir},
		"input missing": {"age-encrypt", "-R", recipients, "-o", out, filepath.Join(dir, "absent")},
		// flags that belong to no age verb
		"unknown long":        {"age-encrypt", "--recipient", recipients, "-o", out, plain},
		"unknown short":       {"age-encrypt", "-r", recipients, "-o", out, plain},
		"armor":               {"age-encrypt", "-a", "-R", recipients, "-o", out, plain},
		"passphrase":          {"age-encrypt", "-p", "secret", "-R", recipients, "-o", out, plain},
		"help flag":           {"age-encrypt", "-h"},
		"force":               {"age-decrypt", "-i", identity, "-f", "-o", out, plain},
		"decrypt takes R":     {"age-decrypt", "-i", identity, "-R", recipients, plain},
		"encrypt takes i":     {"age-encrypt", "-i", identity, "-R", recipients, plain},
		"verbose":             {"age-encrypt", "-R", recipients, "-v", "-o", out, plain},
		"value taken as flag": {"age-encrypt", "-R", "--output", "-o", out, plain},
	}
	for name, args := range cases {
		code, stdout, errs := ageCall(nil, args...)
		if code != exitFatal || len(stdout) != 0 {
			t.Errorf("%s %v: exit %d, %d bytes on stdout, err %q", name, args, code, len(stdout), errs)
			continue
		}
		if !strings.HasPrefix(string(errs), "xtar: "+args[0]+": ") {
			t.Errorf("%s: error %q does not name the verb", name, errs)
		}
		for _, line := range strings.Split(ageSecret(t, identity), "\n") {
			if strings.HasPrefix(line, "AGE-SECRET-KEY-1") && strings.Contains(string(errs), line) {
				t.Errorf("%s: the error printed the private identity", name)
			}
		}
	}
	ageOnly(t, dir, "plain", "bad-recipients.txt", "bad-identity.txt", "empty.txt", "mistake.txt", "wrong-way.txt")
}

// TestAgeDashDash: "--" ends the options, so an input named like a
// flag is an input — and a second one is still one too many.
func TestAgeDashDash(t *testing.T) {
	identity, recipients, _ := ageKeys(t)
	dir := t.TempDir()
	ageWrite(t, filepath.Join(dir, "-odd-input"), "odd\n")
	t.Chdir(dir)
	if code, _, errs := ageCall(nil, "age-encrypt", "-R", recipients, "-o", "-odd-input.age", "--", "-odd-input"); code != exitOK {
		t.Fatalf("encrypt: exit %d: %s", code, errs)
	}
	if code, out, errs := ageCall(nil, "age-decrypt", "-i", identity, "--", "-odd-input.age"); code != exitOK || string(out) != "odd\n" {
		t.Errorf("decrypt: exit %d, %q, %s", code, out, errs)
	}
	if code, _, _ := ageCall(nil, "age-encrypt", "-R", recipients, "--", "-odd-input", "-odd-input"); code != exitFatal {
		t.Errorf("two operands after --: exit %d", code)
	}
	ageOnly(t, dir, "-odd-input", "-odd-input.age")
}

// TestAgeHelp: the three commands are in the usage and in the
// unknown-verb error, and the archive verb still rejects their flags.
func TestAgeHelp(t *testing.T) {
	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	code := Xtar("xtar", nil)
	os.Stderr = old
	w.Close()
	usage, _ := io.ReadAll(r)
	if code != exitFatal {
		t.Fatalf("bare xtar exit %d", code)
	}
	for _, want := range []string{"age-keygen", "age-encrypt", "age-decrypt", "--identity-output", "--recipient-output", "-R RECIPIENTS", "-i IDENTITY"} {
		if !bytes.Contains(usage, []byte(want)) {
			t.Errorf("usage lacks %q:\n%s", want, usage)
		}
	}
	if !bytes.Contains(usage, []byte("{c|x|l|t|i}")) || !bytes.Contains(usage, []byte("--sniff")) {
		t.Errorf("usage lost its archive lines:\n%s", usage)
	}
	if code, _, errs := ageCall(nil, "nope"); code != exitFatal || !strings.Contains(string(errs), "unknown verb") ||
		!strings.Contains(string(errs), "age-keygen, age-encrypt, age-decrypt") {
		t.Errorf("unknown verb: exit %d, %q", code, errs)
	}

	// The archive verb's parser does not know the key flags.
	dir := t.TempDir()
	t.Chdir(dir)
	for _, flag := range []string{"-R", "-i"} {
		code, _, errs := ageCall(nil, "c", flag, "x", "a.tar", ".")
		if code != exitFatal || (!strings.Contains(string(errs), "unrecognized option") && !strings.Contains(string(errs), "invalid option")) {
			t.Errorf("xtar c took %s: exit %d, %q", flag, code, errs)
		}
	}
	ageOnly(t, dir)
}

// TestAgeOutputNeverReplaced: a taken destination — a file, a symlink
// to one, a dangling symlink, a directory — stops the command before
// it reads a byte, and whatever is there is exactly as it was.
func TestAgeOutputNeverReplaced(t *testing.T) {
	identity, recipients, _ := ageKeys(t)
	dir := t.TempDir()
	plain := agePlain(300_000)
	src := ageWrite(t, filepath.Join(dir, "wal"), string(plain))
	cipher := filepath.Join(dir, "wal.age")
	if code, _, errs := ageCall(nil, "age-encrypt", "-R", recipients, "-o", cipher, src); code != exitOK {
		t.Fatalf("setup encrypt: exit %d: %s", code, errs)
	}

	victim := ageWrite(t, filepath.Join(dir, "victim"), "a finished backup that must survive\n")
	if err := os.Symlink(victim, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "nowhere"), filepath.Join(dir, "dangling")); err != nil {
		t.Fatal(err)
	}
	cipherText := ageEncryptBytes(t, recipients, plain)
	taken := []struct{ path, linkTarget string }{
		{victim, ""},                         // a file
		{filepath.Join(dir, "link"), victim}, // a symlink to one
		{filepath.Join(dir, "dangling"), filepath.Join(dir, "nowhere")}, // a symlink to nothing
		{dir, ""}, // a directory
	}
	for _, tc := range taken {
		path := tc.path
		before, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		// Both verbs, from a file and from standard input.
		for _, args := range [][]string{
			{"age-encrypt", "-R", recipients, "-o", path, src},
			{"age-decrypt", "-i", identity, "-o", path, cipher},
			{"age-decrypt", "-i", identity, "--output=" + path, cipher},
		} {
			code, stdout, errs := ageCall(nil, args...)
			if code != exitFatal || len(stdout) != 0 || !strings.Contains(string(errs), "already exists") {
				t.Errorf("%v: exit %d, stdout %d bytes, err %q", args, code, len(stdout), errs)
			}
		}
		for _, args := range [][]string{
			{"age-encrypt", "-R", recipients, "-o", path},
			{"age-decrypt", "-i", identity, "-o", path},
		} {
			code, _, errs := ageCall(bytes.NewReader(plain), args...)
			if args[0] == "age-decrypt" {
				code, _, errs = ageCall(bytes.NewReader(cipherText), args...)
			}
			if code != exitFatal || !strings.Contains(string(errs), "already exists") {
				t.Errorf("%v < stdin: exit %d, %q", args, code, errs)
			}
		}
		after, err := os.Lstat(path)
		if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.ModTime() != after.ModTime() {
			t.Errorf("%s: changed by a refused command: %v", path, err)
		}
		if tc.linkTarget != "" {
			if target, err := os.Readlink(path); err != nil || target != tc.linkTarget {
				t.Errorf("%s: the symlink now points at %q (%v)", path, target, err)
			}
		}
	}
	if got, err := os.ReadFile(victim); err != nil || string(got) != "a finished backup that must survive\n" {
		t.Errorf("the symlink's target was overwritten: %q %v", got, err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "nowhere")); !os.IsNotExist(err) {
		t.Errorf("the dangling symlink's target was created: %v", err)
	}
	ageOnly(t, dir, "wal", "wal.age", "victim", "link", "dangling")
}

// ageEncryptBytes is a ciphertext for a one-off use.
func ageEncryptBytes(t *testing.T, recipients string, plain []byte) []byte {
	t.Helper()
	_, cipher, errs := ageCall(bytes.NewReader(plain), "age-encrypt", "-R", recipients)
	if len(cipher) == 0 || len(errs) != 0 {
		t.Fatalf("encrypt for setup: %d bytes, %s", len(cipher), errs)
	}
	return cipher
}

// TestAgeInputIsNotItsOutput: an output that is the input's own file —
// by the same name, another name, a symlink, or a hard link — is
// refused, and the input is never truncated.
func TestAgeInputIsNotItsOutput(t *testing.T) {
	identity, recipients, _ := ageKeys(t)
	dir := t.TempDir()
	t.Chdir(dir) // relative spellings of one file
	plain := agePlain(150_000)
	src := ageWrite(t, filepath.Join(dir, "wal"), string(plain))
	if err := os.Symlink("wal", filepath.Join(dir, "wal-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link("wal", filepath.Join(dir, "wal-hardlink")); err != nil {
		t.Fatal(err)
	}
	cipher := filepath.Join(dir, "wal.age")
	if code, _, errs := ageCall(nil, "age-encrypt", "-R", recipients, "-o", cipher, src); code != exitOK {
		t.Fatalf("setup encrypt: exit %d: %s", code, errs)
	}

	for name, spellings := range map[string][][2]string{
		"encrypt": {
			{"wal", "wal"}, {"./wal", "wal"}, {"wal", "./wal"}, {"$PWD/wal", "wal"},
			{"wal-link", "wal"}, {"wal", "wal-link"}, {"wal", "wal-hardlink"}, {"wal-hardlink", "wal"},
			{"$PWD/wal", "$PWD/./wal"},
		},
		"decrypt": {
			{"wal.age", "wal.age"}, {"wal.age", "./wal.age"}, {"wal.age", "$PWD/wal.age"},
		},
	} {
		for _, pair := range spellings {
			in, out := strings.ReplaceAll(pair[0], "$PWD", dir), strings.ReplaceAll(pair[1], "$PWD", dir)
			args := []string{"age-encrypt", "-R", recipients, "-o", out, in}
			if name == "decrypt" {
				args = []string{"age-decrypt", "-i", identity, "-o", out, in}
			}
			code, stdout, errs := ageCall(nil, args...)
			if code != exitFatal || len(stdout) != 0 || !strings.Contains(string(errs), "same file") {
				t.Errorf("%s %q → %q: exit %d, err %q", name, pair[0], pair[1], code, errs)
			}
		}
	}
	if got, err := os.ReadFile(src); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("the input was truncated or changed: %d bytes, %v", len(got), err)
	}
	if fi, err := os.Stat(cipher); err != nil || fi.Size() < int64(len(plain)) {
		t.Errorf("the ciphertext was changed: %v", err)
	}
	ageOnly(t, dir, "wal", "wal-link", "wal-hardlink", "wal.age")
}
