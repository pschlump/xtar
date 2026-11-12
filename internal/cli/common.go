/*
Copyright (C) Philip Schlump, 2012-2026.

BSD 3 Clause Licensed.
*/

// Package cli implements the dialects: each native tool's argument
// syntax parsed onto the shared engine.  Everything message-shaped
// (warnings, prompts, exit codes) lives here so the engine stays a
// library.
package cli

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/user"
	"regexp"
	"strconv"
	"strings"

	"github.com/pschlump/xtar/internal/pat"
)

// Exit codes: 0 success, 1 warnings, 2 fatal — the core every one of
// the native tools already shares (see the README).
const (
	exitOK    = 0
	exitWarn  = 1
	exitFatal = 2
)

// env is the running dialect's message context.
type env struct {
	name  string // "tar", "unzip", …
	warns int
}

func (e *env) warnf(format string, args ...any) {
	e.warns++
	fmt.Fprintf(os.Stderr, "%s: %s\n", e.name, fmt.Sprintf(format, args...))
}

// warn adapts warnf to the engine's func(string) warning hooks.
func (e *env) warn(msg string) { e.warnf("%s", msg) }

// note prints an informational line (not a warning, exit code intact).
func (e *env) note(msg string) {
	fmt.Fprintf(os.Stderr, "%s: %s\n", e.name, msg)
}

// fatal prints the message and returns the exit code to propagate.
func (e *env) fatal(format string, args ...any) int {
	fmt.Fprintf(os.Stderr, "%s: %s\n", e.name, fmt.Sprintf(format, args...))
	return exitFatal
}

// stdinReader buffers prompts across calls.
var stdinReader = bufio.NewReader(os.Stdin)

// promptLine asks on stderr and reads one line from stdin.  Single-key
// (raw-mode) answering is deferred with the M4 streaming work; answers
// are line-based for now.
func promptLine(question string) string {
	fmt.Fprint(os.Stderr, question)
	line, err := stdinReader.ReadString('\n')
	if err != nil && line == "" {
		return ""
	}
	return strings.TrimRight(line, "\r\n")
}

// compilePatterns compiles a pattern list, naming the offender on error.
func compilePatterns(list []string) ([]*pat.Pattern, error) {
	var out []*pat.Pattern
	for _, s := range list {
		p, err := pat.Compile(s)
		if err != nil {
			return nil, fmt.Errorf("bad pattern %q: %v", s, err)
		}
		out = append(out, p)
	}
	return out, nil
}

// readList reads a -T/--files-from (or -X exclude) name list; "-" means
// stdin.  With null the separator is NUL instead of newline.
func readList(path string, null bool) ([]string, error) {
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	sep := byte('\n')
	if null {
		sep = 0
	}
	var out []string
	for _, f := range bytes.Split(data, []byte{sep}) {
		s := strings.TrimRight(string(f), "\r")
		if s != "" {
			out = append(out, s)
		}
	}
	return out, nil
}

// parseOwnerArg resolves an --owner/--group value: a numeric id, or a
// name looked up in the system database.
func parseOwnerArg(spec string, isUser bool) (int, error) {
	if id, err := strconv.Atoi(spec); err == nil {
		return id, nil
	}
	if isUser {
		u, err := user.Lookup(spec)
		if err != nil {
			return 0, fmt.Errorf("unknown user %q", spec)
		}
		id, err := strconv.Atoi(u.Uid)
		if err != nil {
			return 0, err
		}
		return id, nil
	}
	g, err := user.LookupGroup(spec)
	if err != nil {
		return 0, fmt.Errorf("unknown group %q", spec)
	}
	id, err := strconv.Atoi(g.Gid)
	if err != nil {
		return 0, err
	}
	return id, nil
}

// humanBytes renders "1.2 MB"-style sizes for --totals/--sniff.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

// compileTransform compiles one GNU tar --transform expression.  Only
// the s/regexp/replacement/[g] command is supported; anything else
// errors clearly rather than being silently ignored.
func compileTransform(expr string) (func(string) string, error) {
	if len(expr) < 3 || expr[0] != 's' {
		return nil, fmt.Errorf("invalid transform %q: only the 's' (substitute) command is supported", expr)
	}
	delim := expr[1]
	if delim == '\\' || delim == '&' || isWordByte(delim) {
		return nil, fmt.Errorf("invalid transform %q: bad delimiter %q", expr, delim)
	}
	var fields []string
	var cur []byte
	for i := 2; i < len(expr); i++ {
		c := expr[i]
		if c == '\\' && i+1 < len(expr) {
			cur = append(cur, c, expr[i+1])
			i++
			continue
		}
		if c == delim {
			fields = append(fields, string(cur))
			cur = nil
			continue
		}
		cur = append(cur, c)
	}
	fields = append(fields, string(cur))
	if len(fields) < 2 {
		return nil, fmt.Errorf("invalid transform %q: missing fields", expr)
	}
	d := string(delim)
	src := strings.ReplaceAll(fields[0], `\`+d, d)
	repl := strings.ReplaceAll(fields[1], `\`+d, d)
	re, err := regexp.Compile(src)
	if err != nil {
		return nil, fmt.Errorf("invalid transform %q: %v", expr, err)
	}
	global := false
	for _, f := range fields[2:] {
		for _, c := range f {
			if c == 'g' {
				global = true
				continue
			}
			return nil, fmt.Errorf("invalid transform %q: flag %q is not supported (only g)", expr, c)
		}
	}
	return func(name string) string {
		return subst(name, re, repl, global)
	}, nil
}

// chainTransforms folds --transform expressions (first to last) into
// one function; nil when there are none.
func chainTransforms(exprs []string) (func(string) string, error) {
	var chain func(string) string
	for _, e := range exprs {
		f, err := compileTransform(e)
		if err != nil {
			return nil, err
		}
		prev := chain
		if prev == nil {
			chain = f
		} else {
			chain = func(s string) string { return f(prev(s)) }
		}
	}
	return chain, nil
}

// subst applies re to name once or globally, expanding & and \1..\9 in
// repl.
func subst(name string, re *regexp.Regexp, repl string, global bool) string {
	var out strings.Builder
	pos := 0
	for pos <= len(name) {
		loc := re.FindStringSubmatchIndex(name[pos:])
		if loc == nil {
			break
		}
		abs := make([]int, len(loc))
		for i, v := range loc {
			abs[i] = v + pos
		}
		out.WriteString(name[pos:abs[0]])
		out.WriteString(expandRepl(repl, name, abs))
		if !global {
			pos = abs[1]
			break
		}
		if abs[1] == abs[0] { // empty match: copy one byte so we always advance
			if abs[1] < len(name) {
				out.WriteByte(name[abs[1]])
			}
			pos = abs[1] + 1
		} else {
			pos = abs[1]
		}
	}
	if pos < len(name) {
		out.WriteString(name[pos:])
	}
	return out.String()
}

func expandRepl(repl, src string, loc []int) string {
	var out strings.Builder
	for i := 0; i < len(repl); i++ {
		c := repl[i]
		if c == '\\' && i+1 < len(repl) {
			n := repl[i+1]
			if n >= '0' && n <= '9' {
				g := int(n - '0')
				if 2*g+1 < len(loc) && loc[2*g] >= 0 {
					out.WriteString(src[loc[2*g]:loc[2*g+1]])
				}
				i++
				continue
			}
			out.WriteByte(n)
			i++
			continue
		}
		if c == '&' {
			out.WriteString(src[loc[0]:loc[1]])
			continue
		}
		out.WriteByte(c)
	}
	return out.String()
}

func isWordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}
