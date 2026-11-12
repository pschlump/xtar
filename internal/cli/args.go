/*
Copyright (C) Philip Schlump, 2012-2026.

BSD 3 Clause Licensed.
*/

package cli

import (
	"fmt"
	"io"
	"strings"
)

// opt describes one dialect option: a long name, a short letter, and
// whether it takes a value.
type opt struct {
	long  string
	short byte
	arg   bool
}

// tok is one parsed option occurrence.
type tok struct {
	o     opt
	name  string // as the user could have written it ("-f", "--file")
	value string
}

// argStream walks argv the way tar/cpio do: long options (--name=v or
// --name v), bundled short options (-cvf x), a dashless first word
// (tar cvf x), and operands — interleaved, so positional options like
// tar's -C keep their place relative to the operands around them.
type argStream struct {
	argv          []string
	specs         []opt
	byLong        map[string]int
	byShort       map[byte]int
	i             int    // next argv index
	bundle        string // pending short letters
	ended         bool   // saw "--"
	dashlessFirst bool   // tar/cpio style: argv[0] may be a dashless bundle
}

func newArgStream(specs []opt, argv []string, dashlessFirst bool) *argStream {
	s := &argStream{
		argv:          argv,
		specs:         specs,
		byLong:        make(map[string]int, len(specs)),
		byShort:       make(map[byte]int, len(specs)),
		dashlessFirst: dashlessFirst,
	}
	for i, o := range specs {
		if o.long != "" {
			s.byLong[o.long] = i
		}
		if o.short != 0 {
			s.byShort[o.short] = i
		}
	}
	return s
}

// Next returns the next option token, or the next operand with a nil
// token.  io.EOF means the argv is exhausted.
func (s *argStream) Next() (*tok, string, error) {
	for {
		if s.bundle != "" {
			c := s.bundle[0]
			s.bundle = s.bundle[1:]
			idx, ok := s.byShort[c]
			if !ok {
				return nil, "", fmt.Errorf("invalid option -- %q", string(c))
			}
			t := &tok{o: s.specs[idx], name: "-" + string(c)}
			if t.o.arg {
				if s.bundle != "" {
					t.value, s.bundle = s.bundle, ""
				} else {
					v, err := s.take()
					if err != nil {
						return nil, "", fmt.Errorf("option %s requires an argument", t.name)
					}
					t.value = v
				}
			}
			return t, "", nil
		}

		if s.i >= len(s.argv) {
			return nil, "", io.EOF
		}
		idx := s.i
		a := s.argv[s.i]
		s.i++

		if s.ended || a == "-" || !strings.HasPrefix(a, "-") {
			if !s.ended && idx == 0 && s.dashlessFirst && a != "-" {
				// The dashless first word is a short bundle (tar cvf x).
				s.bundle = a
				continue
			}
			return nil, a, nil
		}

		if a == "--" {
			s.ended = true
			continue
		}
		if strings.HasPrefix(a, "--") {
			body := a[2:]
			name, val, hasVal := body, "", false
			if eq := strings.IndexByte(body, '='); eq >= 0 {
				name, val, hasVal = body[:eq], body[eq+1:], true
			}
			i, ok := s.byLong[name]
			if !ok {
				return nil, "", fmt.Errorf("unrecognized option '--%s'", name)
			}
			t := &tok{o: s.specs[i], name: "--" + name}
			if t.o.arg {
				if !hasVal {
					v, err := s.take()
					if err != nil {
						return nil, "", fmt.Errorf("option --%s requires an argument", name)
					}
					val = v
				}
			} else if hasVal {
				return nil, "", fmt.Errorf("option '--%s' doesn't allow an argument", name)
			}
			t.value = val
			return t, "", nil
		}

		// Short bundle; "-" alone never reaches here.  GNU-style tools
		// tolerate repeated dashes, so strip them all.
		s.bundle = strings.TrimLeft(a[1:], "-")
	}
}

func (s *argStream) take() (string, error) {
	if s.i >= len(s.argv) {
		return "", io.EOF
	}
	v := s.argv[s.i]
	s.i++
	return v, nil
}
