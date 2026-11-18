/*
Copyright (C) Philip Schlump, 2012-2026.

MIT Licensed.
*/

package pat_test

import (
	"testing"

	"github.com/pschlump/xtar/internal/pat"
)

func TestMatch(t *testing.T) {
	cases := []struct {
		pat, name string
		want      bool
	}{
		{"*.go", "main.go", true},
		{"*.go", "a/b/c.go", true}, // '*' crosses '/'
		{"*.go", "a/b/c.txt", false},
		{"dir/file", "dir/file", true},
		{"dir/file", "dir/file.txt", false},
		{"dir/file*", "dir/file.txt", true},
		{"?.txt", "a.txt", true},
		{"?.txt", "ab.txt", false},
		{"[a-c]*", "beta", true},
		{"[a-c]*", "delta", false},
		{"[!a-c]*", "delta", true},
		{"a/b", "a/b/c", false}, // whole-name match only
		{"*", "anything/at/all", true},
	}
	for _, c := range cases {
		p := pat.MustCompile(c.pat)
		if got := p.Match(c.name); got != c.want {
			t.Errorf("%q.Match(%q) = %v, want %v", c.pat, c.name, got, c.want)
		}
	}
}

func TestDirPattern(t *testing.T) {
	p := pat.MustCompile("dir/")
	if !p.Match("dir") {
		t.Error(`"dir/" should match the directory entry itself`)
	}
	if !pat.IncludeMatch([]*pat.Pattern{p}, "dir/x/y") {
		t.Error(`"dir/" should include members below dir`)
	}
	if pat.IncludeMatch([]*pat.Pattern{p}, "other/x") {
		t.Error(`"dir/" should not include other trees`)
	}
}

func TestIncludeAncestors(t *testing.T) {
	p := pat.MustCompile("src")
	if !pat.IncludeMatch([]*pat.Pattern{p}, "src/main.go") {
		t.Error(`"src" should include members below src`)
	}
}

func TestExcludeSemantics(t *testing.T) {
	build := pat.MustCompile("build")
	if !pat.ExcludeMatch([]*pat.Pattern{build}, "src/build/out.o") {
		t.Error(`excluding "build" should exclude below it`)
	}
	o := pat.MustCompile("*.o")
	if !pat.ExcludeMatch([]*pat.Pattern{o}, "deep/nested/x.o") {
		t.Error(`"*.o" should match at any depth`)
	}
	if pat.ExcludeMatch([]*pat.Pattern{o}, "deep/x.c") {
		t.Error(`"*.o" should not match .c`)
	}
}
