/*
Copyright (C) Philip Schlump, 2012-2026.

MIT Licensed.
*/

// Package pat compiles member-selection patterns with Info-ZIP
// semantics: '*' matches any run of characters including '/', '?'
// matches one character, and '[...]' (or '[!...]') is a character
// class.  Patterns match whole names; "dir/" as a pattern also selects
// everything under dir.
package pat

import (
	"regexp"
	"strings"
)

// Pattern is a compiled selection pattern.
type Pattern struct {
	pat string
	re  *regexp.Regexp
}

// Compile builds a Pattern.
func Compile(p string) (*Pattern, error) {
	re, err := regexp.Compile(translate(p))
	if err != nil {
		return nil, err
	}
	return &Pattern{pat: p, re: re}, nil
}

// MustCompile is Compile for package-level defaults.
func MustCompile(p string) *Pattern {
	q, err := Compile(p)
	if err != nil {
		panic("pat: " + err.Error())
	}
	return q
}

func translate(p string) string {
	var sb strings.Builder
	sb.WriteString("^")
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch c {
		case '*':
			sb.WriteString(".*")
		case '?':
			sb.WriteString(".")
		case '[':
			j := i + 1
			if j < len(p) && (p[j] == '!' || p[j] == '^') {
				j++
			}
			if j < len(p) && p[j] == ']' {
				j++
			}
			for j < len(p) && p[j] != ']' {
				j++
			}
			if j >= len(p) { // unterminated class: literal '['
				sb.WriteString(`\[`)
				continue
			}
			cls := p[i+1 : j]
			neg := ""
			if strings.HasPrefix(cls, "!") || strings.HasPrefix(cls, "^") {
				neg = "^"
				cls = cls[1:]
			}
			cls = strings.ReplaceAll(cls, `\`, `\\`)
			sb.WriteString("[" + neg + cls + "]")
			i = j
		default:
			sb.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	sb.WriteString("$")
	return sb.String()
}

func cleanName(name string) string {
	return strings.TrimPrefix(name, "./")
}

// Match reports whether name is selected by the pattern.
func (p *Pattern) Match(name string) bool {
	name = cleanName(name)
	if p.re.MatchString(name) {
		return true
	}
	// "dir/" also selects the directory entry itself, and a pattern
	// matches a name that is a directory prefix of it.
	if strings.HasSuffix(p.pat, "/") && p.re.MatchString(name+"/") {
		return true
	}
	return false
}

// ancestors lists name and every strict path prefix, e.g. for
// "a/b/c": "a/b/c", "a/b", "a".
func ancestors(name string) []string {
	parts := strings.Split(cleanName(name), "/")
	out := make([]string, 0, len(parts))
	for i := len(parts); i > 0; i-- {
		out = append(out, strings.Join(parts[:i], "/"))
	}
	return out
}

// IncludeMatch applies include semantics: a member is included when a
// pattern matches it or one of its ancestor paths (so "dir" or "dir/"
// selects everything below dir).
func IncludeMatch(pats []*Pattern, name string) bool {
	if len(pats) == 0 {
		return true
	}
	for _, anc := range ancestors(name) {
		for _, p := range pats {
			if p.Match(anc) {
				return true
			}
		}
	}
	return false
}

// ExcludeMatch applies GNU-tar --exclude semantics: the pattern is
// matched against the name and its ancestors (each also by base name
// when the pattern contains no '/').
func ExcludeMatch(pats []*Pattern, name string) bool {
	for _, anc := range ancestors(name) {
		for _, p := range pats {
			if p.Match(anc) {
				return true
			}
			if !strings.Contains(p.pat, "/") && p.Match(baseName(anc)) {
				return true
			}
		}
	}
	return false
}

func baseName(name string) string {
	if i := strings.LastIndexByte(cleanName(name), '/'); i >= 0 {
		return cleanName(name)[i+1:]
	}
	return cleanName(name)
}
