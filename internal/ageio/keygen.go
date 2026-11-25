/*
Copyright (C) Philip Schlump, 2012-2026.

MIT Licensed.
*/

package ageio

import (
	"errors"
	"fmt"
	"os"
	"time"

	"filippo.io/age"
)

// CreateKeyPair generates a new X25519 identity from the system's
// cryptographic random source and writes its two files: the private
// identity (0600) and its public recipient (0644).  The identity is
// returned only when both files were published.
//
// Either both files appear or neither does.  No existing file is
// replaced, and if the recipient file cannot be published the identity
// file just published is taken back — nothing was ever encrypted to
// the key, so nothing is lost by generating a fresh pair.
//
// A non-nil error with a non-nil identity is a *PublishedError or
// wraps one: both files are out and only their durability is in doubt.
func CreateKeyPair(identityPath, recipientPath string) (*age.X25519Identity, error) {
	for _, p := range []string{identityPath, recipientPath} {
		if err := checkAbsent(p); err != nil {
			return nil, err
		}
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, err
	}
	identity, err := Create(identityPath, 0o600)
	if err != nil {
		return nil, err
	}
	defer identity.Abort()
	recipient, err := Create(recipientPath, 0o644)
	if err != nil {
		return nil, err
	}
	defer recipient.Abort()
	if _, err := identity.Write(IdentityFile(id, time.Now())); err != nil {
		return nil, fmt.Errorf("cannot write %s: %w", identityPath, err)
	}
	if _, err := recipient.Write(RecipientFile(id)); err != nil {
		return nil, fmt.Errorf("cannot write %s: %w", recipientPath, err)
	}
	// Abort is a no-op for a file that committed, so the deferred
	// calls only ever clean up after a failure.
	return publishPair(identityPath, id, identity, recipient)
}

// publishPair commits the two staged key files as one unit.  It is
// split from CreateKeyPair so the failure between the two publishes —
// a race for the second name — can be staged in a test.
func publishPair(identityPath string, id *age.X25519Identity, identity, recipient *File) (*age.X25519Identity, error) {
	var warn error
	if err := identity.Commit(); err != nil {
		if !isPublished(err) {
			return nil, err
		}
		warn = fmt.Errorf("identity file: %w", err)
	}
	err := recipient.Commit()
	switch {
	case err == nil:
		return id, warn
	case isPublished(err):
		// Both are out; the recipient's directory just did not sync.
		return id, errors.Join(warn, fmt.Errorf("recipient file: %w", err))
	}
	if rm := os.Remove(identityPath); rm != nil {
		return id, &PublishedError{Path: identityPath,
			Err: fmt.Errorf("its recipient file was not published (%v) and it could not be removed again (%v)", err, rm)}
	}
	return nil, fmt.Errorf("%w — the new identity file was removed again, so neither file exists", err)
}

// isPublished reports whether a Commit error left its file in place.
func isPublished(err error) bool {
	var pub *PublishedError
	return errors.As(err, &pub)
}
