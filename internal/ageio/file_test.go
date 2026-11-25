/*
Copyright (C) Philip Schlump, 2012-2026.

MIT Licensed.
*/

package ageio

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"filippo.io/age"
)

// dirEntries lists a directory, dotfiles included.
func dirEntries(t *testing.T, dir string) []string {
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

func fileMode(t *testing.T, path string) fs.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

// stage is Create + Write of content, the state a finished stream
// leaves behind.
func stage(t *testing.T, path string, perm fs.FileMode, content string) *File {
	t.Helper()
	f, err := Create(path, perm)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	return f
}

// TestFilePublishesWhole: nothing is at the destination until Commit;
// afterwards the content is complete, the mode is exact, and no
// temporary file is left beside it.
func TestFilePublishesWhole(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "000000010000000000000042")
	f := stage(t, path, 0o600, "the whole WAL segment")
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the destination exists before Commit: %v", err)
	}
	tmp := f.tmp
	if filepath.Dir(tmp) != dir || !strings.HasPrefix(filepath.Base(tmp), ".000000010000000000000042.tmp-") {
		t.Fatalf("temporary file %s is not a hidden sibling of the destination", tmp)
	}
	if mode := fileMode(t, tmp); mode != 0o600 {
		t.Errorf("the staged file is mode %o, want 600", mode)
	}
	if err := f.Commit(); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "the whole WAL segment" {
		t.Fatalf("published content %q, %v", got, err)
	}
	if entries := dirEntries(t, dir); len(entries) != 1 || entries[0] != filepath.Base(path) {
		t.Errorf("directory after commit: %v, want only the destination", entries)
	}
	f.Abort() // a no-op after Commit
	if _, err := os.Stat(path); err != nil {
		t.Errorf("Abort after Commit removed the destination: %v", err)
	}
}

// TestFileModesIgnoreUmask: 0600 and 0644 are set exactly, whatever
// the process umask would have made of them.
func TestFileModesIgnoreUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	dir := t.TempDir()

	pub := filepath.Join(dir, "recipients.txt")
	if err := stage(t, pub, 0o644, "public\n").Commit(); err != nil {
		t.Fatal(err)
	}
	if mode := fileMode(t, pub); mode != 0o644 {
		t.Errorf("under umask 077 the public file is %o, want 644", mode)
	}

	syscall.Umask(0o177) // would strip the owner's own bits
	priv := filepath.Join(dir, "identity.txt")
	if err := stage(t, priv, 0o600, "private\n").Commit(); err != nil {
		t.Fatal(err)
	}
	if mode := fileMode(t, priv); mode != 0o600 {
		t.Errorf("under umask 177 the private file is %o, want 600", mode)
	}

	syscall.Umask(0) // would leave the staged 0600 as is, and widen nothing
	if err := stage(t, filepath.Join(dir, "plain"), 0o600, "plaintext\n").Commit(); err != nil {
		t.Fatal(err)
	}
	if mode := fileMode(t, filepath.Join(dir, "plain")); mode != 0o600 {
		t.Errorf("under umask 000 the plaintext is %o, want 600", mode)
	}
}

// TestFileRefusesExisting: a taken destination — a file, a directory,
// a symlink, even a dangling one — is refused with ErrExists before
// anything is staged, and whatever is there is left exactly as it was.
func TestFileRefusesExisting(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("do not touch\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "nowhere"), filepath.Join(dir, "dangling")); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"victim", "link", "dangling", "."} {
		path := filepath.Join(dir, name)
		before, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Create(path, 0o600)
		if !errors.Is(err, ErrExists) {
			t.Errorf("%s: Create returned %v, want ErrExists", name, err)
		}
		after, err := os.Lstat(path)
		if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
			t.Errorf("%s: changed by a refused Create (%v)", name, err)
		}
	}
	if got, err := os.ReadFile(victim); err != nil || string(got) != "do not touch\n" {
		t.Errorf("the symlink's target was overwritten: %q %v", got, err)
	}
	if fi, err := os.Lstat(filepath.Join(dir, "link")); err != nil || fi.Mode()&fs.ModeSymlink == 0 {
		t.Error("the destination symlink was replaced")
	}
	if entries := dirEntries(t, dir); len(entries) != 3 {
		t.Errorf("a refused Create left files behind: %v", entries)
	}
}

// TestFilePublishRace: a destination that appears while the output is
// being written makes Commit fail — nothing is replaced, and the
// staged file is removed.
func TestFilePublishRace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "base.tar.gz.age")
	f := stage(t, path, 0o600, "ours")
	if err := os.WriteFile(path, []byte("theirs"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := f.Commit(); !errors.Is(err, ErrExists) {
		t.Fatalf("Commit over a destination that appeared: %v, want ErrExists", err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "theirs" {
		t.Errorf("the other writer's file was replaced: %q %v", got, err)
	}
	if entries := dirEntries(t, dir); len(entries) != 1 {
		t.Errorf("staged file not removed after the refused publish: %v", entries)
	}
}

// TestFileAbortDiscards: an abandoned output leaves neither a
// destination nor a staged file.
func TestFileAbortDiscards(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out")
	stage(t, path, 0o600, "half").Abort()
	if entries := dirEntries(t, dir); len(entries) != 0 {
		t.Errorf("Abort left %v behind", entries)
	}
	f, err := Create(path, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.Abort()
	if _, err := f.Write([]byte("late")); err == nil {
		t.Error("a write after Abort succeeded")
	}
	if err := f.Commit(); err == nil {
		t.Error("Commit after Abort succeeded")
	}
	if entries := dirEntries(t, dir); len(entries) != 0 {
		t.Errorf("Abort without a write left %v behind", entries)
	}
}

var errDisk = errors.New("no space left on device")

// TestFileWriteFailureIsNotPublished: a write that fails leaves a
// staged file the caller's Abort removes, and a Commit that cannot
// sync or close removes it itself.  Neither publishes anything.
func TestFileWriteFailureIsNotPublished(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out")

	f, err := Create(path, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	f.f.Close() // the disk goes away mid-stream
	if _, err := f.Write([]byte("second")); err == nil {
		t.Fatal("a write to the dead staged file succeeded")
	}
	f.Abort()
	if entries := dirEntries(t, dir); len(entries) != 0 {
		t.Errorf("staged file survived a failed stream: %v", entries)
	}

	// A Commit whose sync fails: close the descriptor underneath it.
	f = stage(t, path, 0o600, "data")
	if err := f.f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Commit(); err == nil {
		t.Fatal("Commit succeeded over a closed file")
	}
	if entries := dirEntries(t, dir); len(entries) != 0 {
		t.Errorf("staged file survived a failed Commit: %v", entries)
	}
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a failed Commit published the destination: %v", err)
	}
}

// TestFilePublishFailure: when the rename itself fails the staged file
// is removed and nothing is published.
func TestFilePublishFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out")
	f := stage(t, path, 0o600, "data")
	// Take the directory away so the rename has nowhere to land.
	if err := os.Remove(f.tmp); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := f.Commit(); err == nil {
		t.Fatal("Commit succeeded without its directory")
	}
}

// TestCheckOutput: the input's own file is refused under any of its
// names, an existing output is refused, and a free one clears.
func TestCheckOutput(t *testing.T) {
	dir := t.TempDir()
	inPath := writeFile(t, filepath.Join(dir, "base.tar.gz"), "plaintext")
	in, err := os.Open(inPath)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	if err := os.Symlink(inPath, filepath.Join(dir, "via-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(inPath, filepath.Join(dir, "via-hardlink")); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"base.tar.gz", "./base.tar.gz", "via-link", "via-hardlink"} {
		if err := CheckOutput(filepath.Join(dir, name), in); err == nil || !strings.Contains(err.Error(), "same file") {
			t.Errorf("%s as output: %v, want the same-file error", name, err)
		}
	}
	other := writeFile(t, filepath.Join(dir, "other"), "x")
	if err := CheckOutput(other, in); !errors.Is(err, ErrExists) {
		t.Errorf("an existing output: %v, want ErrExists", err)
	}
	if err := CheckOutput(filepath.Join(dir, "new.age"), in); err != nil {
		t.Errorf("a free output was refused: %v", err)
	}
	if err := CheckOutput(other, nil); !errors.Is(err, ErrExists) {
		t.Errorf("standard input, existing output: %v, want ErrExists", err)
	}
	if err := CheckOutput(filepath.Join(dir, "new.age"), nil); err != nil {
		t.Errorf("standard input, free output: %v", err)
	}
	if got, err := os.ReadFile(inPath); err != nil || string(got) != "plaintext" {
		t.Errorf("the input was modified by an output check: %q %v", got, err)
	}
}

// TestCreateKeyPair: both files appear with exact modes and standard
// content, and an existing file on either side refuses the whole pair
// without touching it.
func TestCreateKeyPair(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	dir := t.TempDir()
	identityPath := filepath.Join(dir, "identity.txt")
	recipientPath := filepath.Join(dir, "recipients.txt")

	taken := writeFile(t, recipientPath, "the old recipients\n")
	if id, err := CreateKeyPair(identityPath, recipientPath); id != nil || !errors.Is(err, ErrExists) {
		t.Fatalf("an existing recipients file: id %v, err %v", id, err)
	}
	if entries := dirEntries(t, dir); len(entries) != 1 {
		t.Errorf("a refused key pair left files behind: %v", entries)
	}
	if got, err := os.ReadFile(taken); err != nil || string(got) != "the old recipients\n" {
		t.Errorf("the existing recipients file was modified: %q %v", got, err)
	}
	if err := os.Remove(taken); err != nil {
		t.Fatal(err)
	}
	writeFile(t, identityPath, "the old identity\n")
	if id, err := CreateKeyPair(identityPath, recipientPath); id != nil || !errors.Is(err, ErrExists) {
		t.Fatalf("an existing identity file: id %v, err %v", id, err)
	}
	if _, err := os.Lstat(recipientPath); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a recipient file was published beside a refused identity: %v", err)
	}
	if err := os.Remove(identityPath); err != nil {
		t.Fatal(err)
	}

	id, err := CreateKeyPair(identityPath, recipientPath)
	if err != nil || id == nil {
		t.Fatalf("CreateKeyPair: %v", err)
	}
	if mode := fileMode(t, identityPath); mode != 0o600 {
		t.Errorf("identity file mode %o, want 600", mode)
	}
	if mode := fileMode(t, recipientPath); mode != 0o644 {
		t.Errorf("recipients file mode %o, want 644", mode)
	}
	if got, err := os.ReadFile(recipientPath); err != nil || string(got) != id.Recipient().String()+"\n" {
		t.Errorf("recipients file %q, %v", got, err)
	}
	ids, err := LoadIdentities([]string{identityPath})
	if err != nil || len(ids) != 1 {
		t.Fatalf("our own identity file does not load: %v", err)
	}
	back, ok := ids[0].(*age.X25519Identity)
	if !ok || back.Recipient().String() != id.Recipient().String() {
		t.Fatal("the identity file holds a different key than the returned identity")
	}
	next, err := CreateKeyPair(filepath.Join(dir, "i2"), filepath.Join(dir, "r2"))
	if err != nil || next == nil || next.Recipient().String() == id.Recipient().String() {
		t.Fatalf("the second key pair did not generate a fresh key: %v", err)
	}
	if entries := dirEntries(t, dir); len(entries) != 4 {
		t.Errorf("files after two key pairs: %v", entries)
	}
}

// TestCreateKeyPairRollback: when the recipients file loses a race for
// its name, the identity file already published is taken back, so a
// rerun starts clean instead of from half a pair.
func TestCreateKeyPairRollback(t *testing.T) {
	dir := t.TempDir()
	identityPath, recipientPath := filepath.Join(dir, "identity.txt"), filepath.Join(dir, "recipients.txt")
	id := testKey(t)

	identity, err := Create(identityPath, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer identity.Abort()
	recipient, err := Create(recipientPath, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer recipient.Abort()
	identity.Write(IdentityFile(id, time.Now()))
	recipient.Write(RecipientFile(id))

	// The race: someone takes the recipients name before it publishes.
	rival := writeFile(t, recipientPath, "a rival recipients file\n")
	if got, err := publishPair(identityPath, id, identity, recipient); got != nil || !errors.Is(err, ErrExists) {
		t.Fatalf("publishPair returned %v, %v; want no identity and ErrExists", got, err)
	}
	if _, err := os.Lstat(identityPath); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the identity file survived a failed pair: %v", err)
	}
	if got, err := os.ReadFile(rival); err != nil || string(got) != "a rival recipients file\n" {
		t.Errorf("the rival's recipients file was modified: %q %v", got, err)
	}
	if entries := dirEntries(t, dir); len(entries) != 1 {
		t.Errorf("staged files survived the rollback: %v", entries)
	}
}

// TestSyncDir: a real directory syncs; one that cannot be synced is
// not an error, one that cannot be opened is.
func TestSyncDir(t *testing.T) {
	if err := syncDir(t.TempDir()); err != nil {
		t.Errorf("syncing a directory: %v", err)
	}
	if err := syncDir(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("syncing a missing directory succeeded")
	}
	for _, unsupported := range []error{syscall.EINVAL, syscall.ENOTSUP, errors.ErrUnsupported} {
		if err := ignoreUnsupported(unsupported); err != nil {
			t.Errorf("%v is reported as a failure", unsupported)
		}
	}
	if err := ignoreUnsupported(errDisk); !errors.Is(err, errDisk) {
		t.Error("a real sync error was swallowed")
	}
}
