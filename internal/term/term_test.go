/*
Copyright (C) Philip Schlump, 2012-2026.

MIT Licensed.
*/

package term

import (
	"os"
	"testing"
)

// TestNoEchoNonTerminal: on a pipe (as under `go test`) NoEcho must
// degrade to a no-op restore — piped passwords still read.
func TestNoEchoNonTerminal(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = old
		r.Close()
		w.Close()
	})
	restore := NoEcho()
	if restore == nil {
		t.Fatal("restore function is nil")
	}
	restore() // must not panic
	restore() // idempotent enough for defensive callers
}
