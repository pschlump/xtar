/*
Copyright (C) Philip Schlump, 2012-2026.

MIT Licensed.
*/

package ageio

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

// testKey returns a fresh X25519 identity.  Every test generates its
// own; none is ever stored outside t.TempDir().
func testKey(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func recipientsOf(ids ...*age.X25519Identity) []age.Recipient {
	var rs []age.Recipient
	for _, id := range ids {
		rs = append(rs, id.Recipient())
	}
	return rs
}

func identitiesOf(ids ...*age.X25519Identity) []age.Identity {
	var is []age.Identity
	for _, id := range ids {
		is = append(is, id)
	}
	return is
}

// rendered is a recipient as age prints it, failing the test if it is
// not an X25519 one.
func rendered(t *testing.T, r age.Recipient) string {
	t.Helper()
	x, ok := r.(*age.X25519Recipient)
	if !ok {
		t.Fatalf("recipient is %T, want *age.X25519Recipient", r)
	}
	return x.String()
}

func writeFile(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestKeyFilesAreStandardAge: what IdentityFile and RecipientFile
// render, age's own parsers read back as the same key.
func TestKeyFilesAreStandardAge(t *testing.T) {
	id := testKey(t)
	created := time.Date(2026, 11, 25, 9, 30, 0, 0, time.UTC)

	rec := RecipientFile(id)
	if want := id.Recipient().String() + "\n"; string(rec) != want {
		t.Fatalf("recipients file is %q, want exactly the recipient and a newline", rec)
	}
	parsed, err := age.ParseRecipients(bytes.NewReader(rec))
	if err != nil || len(parsed) != 1 || rendered(t, parsed[0]) != id.Recipient().String() {
		t.Fatalf("age cannot parse our recipients file: %v %+v", err, parsed)
	}

	// Exactly age-keygen's three lines.  (A failure reports the shape,
	// never the content: it is a private key, test-generated or not.)
	ident := IdentityFile(id, created)
	want := "# created: 2026-11-25T09:30:00Z\n# public key: " + id.Recipient().String() + "\n" + id.String() + "\n"
	if string(ident) != want {
		lines := strings.Count(string(ident), "\n")
		t.Fatalf("identity file is %d lines, %d bytes; want age-keygen's 3 lines, %d bytes",
			lines, len(ident), len(want))
	}
	// The older age-keygen layout, a blank line before the key, is the
	// same file to a reader.
	ids, err := age.ParseIdentities(bytes.NewReader(ident))
	if err != nil || len(ids) != 1 {
		t.Fatalf("age cannot parse our identity file: %v %+v", err, ids)
	}
	if x, ok := ids[0].(*age.X25519Identity); !ok || x.Recipient().String() != id.Recipient().String() {
		t.Fatal("age read a different key from our identity file")
	}
	if ids, err = age.ParseIdentities(strings.NewReader("# created: then\n# public key: " + id.Recipient().String() + "\n\n" + id.String() + "\n")); err != nil || len(ids) != 1 {
		t.Fatalf("age cannot parse the older blank-line identity layout: %v", err)
	}
	if ids, err = LoadIdentities([]string{writeFile(t, filepath.Join(t.TempDir(), "i.txt"), string(ident))}); err != nil || len(ids) != 1 {
		t.Fatalf("our own loader rejects our identity file: %v", err)
	}
}

// TestParseRecipients: comments, blank lines, CRLF and stray blanks are
// tolerated, order is kept, and repeats within or across files drop out.
func TestParseRecipients(t *testing.T) {
	a, b, c := testKey(t), testKey(t), testKey(t)
	dir := t.TempDir()

	first := "# backup host key\n\n" + a.Recipient().String() + "\r\n   \n\t" +
		b.Recipient().String() + "  \n" + a.Recipient().String() + "\n"
	// A file holding only keys the first file already had is fine.
	second := "  " + b.Recipient().String() + "\n\n# rotation key\n" + c.Recipient().String()

	recs, err := LoadRecipients([]string{writeFile(t, filepath.Join(dir, "one.txt"), first),
		writeFile(t, filepath.Join(dir, "two.txt"), second)})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range recs {
		got = append(got, rendered(t, r))
	}
	want := []string{a.Recipient().String(), b.Recipient().String(), c.Recipient().String()}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("recipients %v, want %v", got, want)
	}
}

// TestParseRecipientsRejects: anything that is not an X25519 recipient
// fails the whole set, naming file and line — and never the line.
func TestParseRecipientsRejects(t *testing.T) {
	secret := testKey(t) // the canary: a real private key in the wrong file
	good := testKey(t).Recipient().String()
	valid := testKey(t).Recipient().String()
	damaged := valid[:len(valid)-1] + "q" // breaks the bech32 checksum
	if valid[len(valid)-1] == 'q' {
		damaged = valid[:len(valid)-1] + "p"
	}

	for _, tc := range []struct {
		name, line, want string
	}{
		{"not a key", "not-a-key", "not an age1"},
		{"checksum", damaged, "malformed"},
		{"truncated", good[:40], "malformed"},
		{"uppercase", strings.ToUpper(good), "not an age1"},
		{"two on a line", good + " " + valid, "malformed"},
		{"trailing comment", good + " # host", "malformed"},
		{"private key", secret.String(), "private identity"},
		{"hybrid", "age1pq1qqqq", "post-quantum"},
		{"plugin", "age1yubikey1PUB", "plugin"},
		{"ssh", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample", "SSH"},
		{"pem", "-----BEGIN AGE ENCRYPTED FILE-----", "not an age1"},
	} {
		path := writeFile(t, filepath.Join(t.TempDir(), "recipients.txt"), "# comment\n\n"+good+"\n"+tc.line+"\n")
		_, err := LoadRecipients([]string{path})
		if err == nil {
			t.Fatalf("%s: accepted %q", tc.name, tc.line)
		}
		if !strings.Contains(err.Error(), "recipients.txt: line 4:") || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %q does not name the file, line 4, and %q", tc.name, err, tc.want)
		}
		if strings.Contains(err.Error(), tc.line) || strings.Contains(err.Error(), secret.String()) {
			t.Errorf("%s: error %q quotes the key file", tc.name, err)
		}
	}
}

// TestParseRecipientsEmpty: a file with no recipient at all is a
// misconfiguration, not an empty set to encrypt to nobody with.
func TestParseRecipientsEmpty(t *testing.T) {
	for name, content := range map[string]string{"empty": "", "comments": "# nothing\n\n# here\n"} {
		path := writeFile(t, filepath.Join(t.TempDir(), "recipients.txt"), content)
		if _, err := LoadRecipients([]string{path}); err == nil {
			t.Errorf("%s recipients file was accepted", name)
		}
	}
}

// TestKeyFileReadsBounded: a key file is a small text file.  A missing
// one, a directory, or anything over MaxKeyFileBytes is refused.
func TestKeyFileReadsBounded(t *testing.T) {
	dir := t.TempDir()
	id := testKey(t)
	if _, err := LoadIdentities([]string{filepath.Join(dir, "missing.txt")}); err == nil {
		t.Error("a missing identity file was accepted")
	}
	if _, err := LoadRecipients([]string{dir}); err == nil || !strings.Contains(err.Error(), "is a directory") {
		t.Errorf("a directory as recipients file: %v", err)
	}

	big := writeFile(t, filepath.Join(dir, "big.txt"), id.Recipient().String()+"\n")
	f, err := os.OpenFile(big, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(bytes.Repeat([]byte("#"), MaxKeyFileBytes)); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := LoadRecipients([]string{big}); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("an oversized recipients file: %v", err)
	}
}

// TestParseIdentities: the standard identity file shape — comments,
// blank lines, one key per line — parses, cumulatively across files.
func TestParseIdentities(t *testing.T) {
	a, b := testKey(t), testKey(t)
	dir := t.TempDir()
	path := writeFile(t, filepath.Join(dir, "a.txt"), string(IdentityFile(a, time.Now())))
	if ids, err := LoadIdentities([]string{path, path}); err != nil || len(ids) != 1 {
		t.Fatalf("the same identity file twice: %v, %d identities", err, len(ids))
	}
	other := writeFile(t, filepath.Join(dir, "b.txt"), "  "+b.String()+"\r\n")
	ids, err := LoadIdentities([]string{path, other})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, i := range ids {
		id, ok := i.(*age.X25519Identity)
		if !ok {
			t.Fatalf("identity is not X25519: %T", i)
		}
		got = append(got, id.Recipient().String())
	}
	if want := a.Recipient().String() + "," + b.Recipient().String(); strings.Join(got, ",") != want {
		t.Fatalf("identities %v, want %v", got, want)
	}
}

// TestParseIdentitiesRejects: only X25519 AGE-SECRET-KEY-1 lines pass;
// no error ever carries the line it rejected.
// otherChar replaces one Bech32 character of an identity with another
// valid one.  The checksum then breaks whatever the original was: 'Q'
// is itself in the charset, so "swap in a Q" would leave one key in 32
// untouched — and a valid key must be accepted.
func otherChar(identity string, i int) string {
	b := []byte(identity)
	if b[i] == 'Q' {
		b[i] = 'P'
	} else {
		b[i] = 'Q'
	}
	return string(b)
}

func TestParseIdentitiesRejects(t *testing.T) {
	good := testKey(t)
	canary := testKey(t).String()
	for _, tc := range []struct {
		name, line, want string
	}{
		{"malformed", otherChar(canary, len(canary)-1), "malformed"},
		{"checksum", otherChar(canary, 70), "malformed"},
		{"truncated", canary[:40], "malformed"},
		{"hybrid", "AGE-SECRET-KEY-PQ-1" + canary[len("AGE-SECRET-KEY-1"):], "post-quantum"},
		{"recipient", good.Recipient().String(), "public recipient"},
		{"ssh private key", "-----BEGIN OPENSSH PRIVATE KEY-----", "PEM and SSH"},
		{"passphrase", "correct horse battery staple", "not an AGE-SECRET-KEY-1"},
		{"empty-ish", "\x00", "not an AGE-SECRET-KEY-1"},
	} {
		if id, err := age.ParseX25519Identity(tc.line); err == nil && !strings.HasPrefix(tc.line, "AGE-SECRET-KEY-PQ-1") {
			// Guard on the test itself: the "corrupt" key must really be
			// corrupt, or the case proves nothing.
			t.Fatalf("%s: the sample %q is a valid identity (%v)", tc.name, id.Recipient(), err)
		}
		path := writeFile(t, filepath.Join(t.TempDir(), "identity.txt"), "# created: just now\n"+good.String()+"\n"+tc.line+"\n")
		_, err := LoadIdentities([]string{path})
		if err == nil {
			t.Errorf("%s: accepted", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), "identity.txt: line 3:") || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %q does not name the file, line 3, and %q", tc.name, err, tc.want)
		}
		if strings.Contains(err.Error(), tc.line) || strings.Contains(err.Error(), good.String()) {
			t.Errorf("%s: error %q quotes private key material", tc.name, err)
		}
	}
}

// errReader fails after delivering its data; it stands in for a source
// that dies mid-stream.
type errReader struct {
	data []byte
	err  error
}

func (r *errReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

var errSource = errors.New("source read error")
