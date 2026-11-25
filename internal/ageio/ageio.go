/*
Copyright (C) Philip Schlump, 2012-2026.

MIT Licensed.
*/

// Package ageio is xtar's streaming file encryption: standard age v1
// with X25519 keys, delegated end to end to filippo.io/age, plus the
// publish-on-success file output the backup commands depend on (see
// file.go).
//
// No payload is ever held in memory.  Plaintext and ciphertext pass
// through io.Reader/io.Writer and the age streaming API one 64 KiB
// chunk at a time, so a multi-GiB base backup runs in bounded memory.
package ageio

import (
	"errors"
	"fmt"
	"io"
	"iter"
	"os"
	"strings"
	"time"

	"filippo.io/age"
)

// MaxKeyFileBytes bounds how much of a recipients or identity file is
// read.  Key files are lines of 62–74 characters; the bound only stops
// a data file named as a key file from being pulled into memory.
const MaxKeyFileBytes = 1 << 20

// ChunkSize is the age payload chunk size: the amount of plaintext
// behind each authenticated ciphertext chunk, and so the granularity
// at which ciphertext appears behind plaintext.
const ChunkSize = 64 * 1024

// ErrNoIdentityMatch reports an age file that none of the given
// identities can open: the wrong key, or a file encrypted to other
// recipients.
var ErrNoIdentityMatch = errors.New("no identity matched the recipients this file is encrypted to")

var errNoKeys = errors.New("no keys found")

// LoadRecipients parses the recipients files in order, cumulatively,
// dropping repeated recipients.  Only X25519 (age1…) recipients are
// accepted: a malformed or unsupported line fails the whole set.
func LoadRecipients(paths []string) ([]age.Recipient, error) {
	var recs []age.Recipient
	seen := make(map[string]bool)
	for _, p := range paths {
		data, err := readKeyFile(p)
		if err != nil {
			return nil, err
		}
		rs, err := parseRecipients(data, seen)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		recs = append(recs, rs...)
	}
	return recs, nil
}

// LoadIdentities parses the identity files in order, cumulatively,
// dropping repeated identities.  Only X25519 (AGE-SECRET-KEY-1…)
// identities are accepted: a malformed or unsupported line fails the
// whole set.
func LoadIdentities(paths []string) ([]age.Identity, error) {
	var ids []age.Identity
	seen := make(map[string]bool)
	for _, p := range paths {
		data, err := readKeyFile(p)
		if err != nil {
			return nil, err
		}
		is, err := parseIdentities(data, seen)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		ids = append(ids, is...)
	}
	return ids, nil
}

// readKeyFile reads a recipients or identity file, never more than
// MaxKeyFileBytes.  This is the one deliberate bounded read in the
// package; payload data only ever streams.
func readKeyFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if fi, err := f.Stat(); err != nil {
		return nil, err
	} else if fi.IsDir() {
		return nil, fmt.Errorf("%s is a directory, not a key file", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxKeyFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	if len(data) > MaxKeyFileBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes, not a key file", path, MaxKeyFileBytes)
	}
	return data, nil
}

// keyLines yields the meaningful lines of a key file with their
// 1-based numbers: blank lines and comments are skipped.  It accepts
// every standard age key file and is more forgiving of whitespace —
// surrounding blanks and a CRLF ending are ignored.  A "#" comments
// only from the start of a line, as with age itself.
func keyLines(data []byte) iter.Seq2[int, string] {
	return func(yield func(int, string) bool) {
		for n, raw := range strings.Split(string(data), "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || line[0] == '#' {
				continue
			}
			if !yield(n+1, line) {
				return
			}
		}
	}
}

// parseRecipients parses one recipients file.  seen carries the
// key lines already loaded so repeats across files are dropped.
//
// No error quotes the offending line: a recipients file is the place
// a private key is most easily pasted by mistake, and these errors go
// to standard error and logs.
func parseRecipients(data []byte, seen map[string]bool) ([]age.Recipient, error) {
	var recs []age.Recipient
	found := 0 // valid keys in this file, repeats included
	for n, line := range keyLines(data) {
		switch {
		case strings.HasPrefix(line, "AGE-SECRET-KEY-"):
			return nil, fmt.Errorf("line %d: a private identity was found in a recipients file (want its public age1… key)", n)
		case strings.HasPrefix(line, "age1pq1"):
			return nil, fmt.Errorf("line %d: unsupported recipient type (post-quantum hybrid age1pq1 recipients are not supported, only X25519 age1…)", n)
		case isPluginRecipient(line):
			// It would hand the key wrapping to an external program.
			return nil, fmt.Errorf("line %d: unsupported recipient type (plugin recipients are not supported, only X25519 age1…)", n)
		case strings.HasPrefix(line, "age1"):
			r, err := age.ParseX25519Recipient(line)
			if err != nil {
				return nil, fmt.Errorf("line %d: malformed recipient (not a valid age1… public key)", n)
			}
			found++
			if !seen[line] {
				seen[line] = true
				recs = append(recs, r)
			}
		case strings.HasPrefix(line, "ssh-"):
			return nil, fmt.Errorf("line %d: unsupported recipient type (SSH recipients are not supported, only X25519 age1…)", n)
		default:
			return nil, fmt.Errorf("line %d: not an age1… recipient", n)
		}
	}
	if found == 0 {
		return nil, errNoKeys
	}
	return recs, nil
}

// parseIdentities parses one identity file; seen is as in
// parseRecipients.  As there, no error quotes the line: identity
// files hold private keys.
func parseIdentities(data []byte, seen map[string]bool) ([]age.Identity, error) {
	var ids []age.Identity
	found := 0 // valid keys in this file, repeats included
	for n, line := range keyLines(data) {
		switch {
		case strings.HasPrefix(line, "AGE-SECRET-KEY-PQ-1"):
			return nil, fmt.Errorf("line %d: unsupported identity type (post-quantum hybrid AGE-SECRET-KEY-PQ-1 identities are not supported, only X25519 AGE-SECRET-KEY-1…)", n)
		case strings.HasPrefix(line, "AGE-SECRET-KEY-1"):
			id, err := age.ParseX25519Identity(line)
			if err != nil {
				return nil, fmt.Errorf("line %d: malformed identity (not a valid AGE-SECRET-KEY-1… key)", n)
			}
			found++
			if !seen[line] {
				seen[line] = true
				ids = append(ids, id)
			}
		case strings.HasPrefix(line, "age1"):
			return nil, fmt.Errorf("line %d: a public recipient was found where a private identity is expected (want AGE-SECRET-KEY-1…)", n)
		case strings.HasPrefix(line, "-----BEGIN"):
			return nil, fmt.Errorf("line %d: unsupported identity type (PEM and SSH keys are not supported, only X25519 AGE-SECRET-KEY-1…)", n)
		default:
			return nil, fmt.Errorf("line %d: not an AGE-SECRET-KEY-1… identity", n)
		}
	}
	if found == 0 {
		return nil, errNoKeys
	}
	return ids, nil
}

// isPluginRecipient reports the age1<plugin>1… spelling: a lowercase
// alphanumeric plugin name between two "1" separators, which an X25519
// recipient never has (the bech32 data part has no "1").
func isPluginRecipient(line string) bool {
	name, _, found := strings.Cut(strings.TrimPrefix(line, "age1"), "1")
	return found && strings.Trim(name, "abcdefghijklmnopqrstuvwxyz0123456789") == ""
}

// IdentityFile renders an identity file the way age-keygen writes one:
// a "created" line, the matching public key as a comment, the identity.
// age itself reads this format, so the file moves between the tools
// unchanged.  The content is secret: it belongs in a 0600 file and
// nowhere else.
func IdentityFile(id *age.X25519Identity, created time.Time) []byte {
	return []byte(fmt.Sprintf("# created: %s\n# public key: %s\n%s\n",
		created.Format(time.RFC3339), id.Recipient(), id))
}

// RecipientFile renders a recipients file: the public recipient and a
// newline, nothing else, so scripts can read it as a single value.
func RecipientFile(id *age.X25519Identity) []byte {
	return []byte(id.Recipient().String() + "\n")
}

// Encrypt writes to dst the age file of everything read from src, as
// the plaintext arrives.  The age writer's Close finalizes the last
// authenticated chunk, so its error is the operation's error.
func Encrypt(dst io.Writer, src io.Reader, recipients []age.Recipient) error {
	w, err := age.Encrypt(dst, recipients...)
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, src); err != nil {
		return err
	}
	return w.Close()
}

// DecryptReader returns the plaintext of the age file on src.  The
// header is parsed and the identities tried before it returns, so a
// wrong identity or a non-age input fails before any output exists.
//
// The final chunk authenticates only at EOF: a corrupt or truncated
// file fails after its intact prefix has already been read.  Callers
// that must never expose that prefix publish through File.
func DecryptReader(src io.Reader, identities []age.Identity) (io.Reader, error) {
	r, err := age.Decrypt(src, identities...)
	if err != nil {
		var noMatch *age.NoIdentityMatchError
		if errors.As(err, &noMatch) {
			return nil, ErrNoIdentityMatch
		}
		return nil, err
	}
	return r, nil
}

// Decrypt writes to dst the plaintext of the age file on src and
// returns the plaintext length.  A file that fails authentication
// anywhere, final chunk included, returns an error.
func Decrypt(dst io.Writer, src io.Reader, identities []age.Identity) (int64, error) {
	r, err := DecryptReader(src, identities)
	if err != nil {
		return 0, err
	}
	return io.Copy(dst, r)
}
