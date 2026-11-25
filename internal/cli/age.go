/*
Copyright (C) Philip Schlump, 2012-2026.

MIT Licensed.
*/

package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/pschlump/xtar/internal/ageio"
)

// The age verbs' option surfaces.  Each verb parses against its own
// list, ahead of the archive flags, so here -i and -R are key files
// whatever they mean elsewhere.
var (
	ageKeygenSpecs = []opt{
		{long: "identity-output", arg: true},
		{long: "recipient-output", arg: true},
	}
	ageEncryptSpecs = []opt{
		{long: "recipient-file", short: 'R', arg: true},
		{long: "output", short: 'o', arg: true},
	}
	ageDecryptSpecs = []opt{
		{long: "identity-file", short: 'i', arg: true},
		{long: "output", short: 'o', arg: true},
	}
)

// ageCmd dispatches the three file-encryption verbs: age-keygen,
// age-encrypt, age-decrypt (see the README's "Encrypting backups").
func ageCmd(e *env, verb string, args []string) int {
	switch verb {
	case "age-keygen":
		return ageKeygen(e, args)
	case "age-encrypt":
		return ageEncrypt(e, args)
	default:
		return ageDecrypt(e, args)
	}
}

// ageParse runs the option loop the age verbs share: every option goes
// to handle, every operand is appended to operands.
func ageParse(specs []opt, args []string, operands *[]string, handle func(*tok) error) error {
	st := newArgStream(specs, args, false)
	for {
		t, arg, err := st.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if t == nil {
			*operands = append(*operands, arg)
			continue
		}
		if err := handle(t); err != nil {
			return err
		}
	}
}

// ageKeygen is `xtar age-keygen --identity-output PATH
// --recipient-output PATH`: a fresh X25519 identity written privately
// (0600) beside its public recipient (0644), neither replacing an
// existing file.  Standard output carries the recipient and nothing
// else; the identity goes to its file, never to a stream.
func ageKeygen(e *env, args []string) int {
	const verb = "age-keygen"
	var identityPath, recipientPath string
	var haveIdentity, haveRecipient bool
	var operands []string
	err := ageParse(ageKeygenSpecs, args, &operands, func(t *tok) error {
		if t.value == "" {
			return fmt.Errorf("%s needs a path", t.name)
		}
		switch t.o.long {
		case "identity-output":
			if haveIdentity {
				return fmt.Errorf("%s was given more than once", t.name)
			}
			identityPath, haveIdentity = t.value, true
		case "recipient-output":
			if haveRecipient {
				return fmt.Errorf("%s was given more than once", t.name)
			}
			recipientPath, haveRecipient = t.value, true
		}
		return nil
	})
	switch {
	case err != nil:
		return e.fatal("%s: %v", verb, err)
	case len(operands) > 0:
		return e.fatal("%s: unexpected operand %q (it takes only --identity-output and --recipient-output)", verb, operands[0])
	case !haveIdentity && !haveRecipient:
		return e.fatal("%s: --identity-output PATH and --recipient-output PATH are both required", verb)
	case !haveIdentity:
		return e.fatal("%s: --identity-output PATH is required", verb)
	case !haveRecipient:
		return e.fatal("%s: --recipient-output PATH is required", verb)
	case filepath.Clean(identityPath) == filepath.Clean(recipientPath):
		return e.fatal("%s: --identity-output and --recipient-output must name two different files (the identity is private, the recipient public)", verb)
	}

	id, err := ageio.CreateKeyPair(identityPath, recipientPath)
	if id != nil {
		// Both files are published; an error now is only a durability
		// warning, so the recipient is reported like any success.
		fmt.Println(id.Recipient())
	}
	if err != nil {
		if id != nil {
			e.warnf("%s: %v", verb, err)
			return exitWarn
		}
		return e.fatal("%s: %v", verb, err)
	}
	e.note(fmt.Sprintf("%s: wrote the identity to %s (mode 0600) and its recipient to %s (mode 0644)",
		verb, identityPath, recipientPath))
	return exitOK
}

// ageArgs is a parsed age-encrypt or age-decrypt command line.
type ageArgs struct {
	keys   []string // -R / -i files, in the order given
	output string   // -o; "" writes to standard output
	input  string   // the operand; "" reads standard input
}

// parseAgeIO parses the shared surface: repeatable key-file options,
// one -o/--output, at most one input operand.  keyFlag names the
// verb's key option in the "missing" message.
func parseAgeIO(specs []opt, keyFlag string, args []string) (*ageArgs, error) {
	a := &ageArgs{}
	var operands []string
	outputSeen := false
	err := ageParse(specs, args, &operands, func(t *tok) error {
		switch t.o.long {
		case "recipient-file", "identity-file":
			if t.value == "" || t.value == "-" {
				return fmt.Errorf("%s needs a key file path, not %q", t.name, t.value)
			}
			a.keys = append(a.keys, t.value)
		case "output":
			// One output per run, whatever the value: two -o flags is
			// a script bug worth stopping whatever they say.
			if outputSeen {
				return fmt.Errorf("%s was given more than once", t.name)
			}
			outputSeen = true
			if t.value == "" {
				return fmt.Errorf("%s needs a path (\"-\" writes to standard output)", t.name)
			}
			a.output = t.value
		}
		return nil
	})
	switch {
	case err != nil:
		return nil, err
	case len(operands) > 1:
		return nil, fmt.Errorf("too many operands (%s): one input file, or none for standard input",
			strings.Join(operands, " "))
	case len(operands) == 1 && operands[0] == "":
		return nil, errors.New("empty input path")
	case len(a.keys) == 0:
		return nil, fmt.Errorf("need at least one %s FILE", keyFlag)
	}
	if len(operands) == 1 && operands[0] != "-" {
		a.input = operands[0]
	}
	if a.output == "-" {
		a.output = ""
	}
	return a, nil
}

// ageSource is an input stream, with the name diagnostics give it and,
// for a file, its handle.
type ageSource struct {
	io.Reader
	file *os.File // nil for standard input
	name string
}

// ageStdin opens standard input.  The tests replace it to feed a
// source that fails mid-stream.
var ageStdin = func() ageSource { return ageSource{Reader: os.Stdin, name: "standard input"} }

// ageInput opens the input file; "" reads standard input.
func ageInput(path string) (ageSource, error) {
	if path == "" {
		return ageStdin(), nil
	}
	f, err := os.Open(path)
	if err != nil {
		return ageSource{}, err
	}
	fi, serr := f.Stat()
	if serr == nil && fi.IsDir() {
		serr = fmt.Errorf("%s is a directory", path)
	}
	if serr != nil {
		_ = f.Close()
		return ageSource{}, serr
	}
	return ageSource{Reader: f, file: f, name: path}, nil
}

func (s ageSource) close() {
	if s.file != nil && s.file != os.Stdin {
		_ = s.file.Close()
	}
}

// ageStage is a file output under construction: a temporary file until
// Commit publishes it.  *ageio.File is the implementation; the tests
// substitute failing ones.
type ageStage interface {
	io.Writer
	Commit() error
	Abort()
}

var newAgeStage = func(path string) (ageStage, error) { return ageio.Create(path, 0o600) }

// ageEncrypt is `xtar age-encrypt -R RECIPIENTS [-o OUTPUT] [INPUT]`.
func ageEncrypt(e *env, args []string) int {
	const verb = "age-encrypt"
	a, err := parseAgeIO(ageEncryptSpecs, "--recipient-file", args)
	if err != nil {
		return e.fatal("%s: %v", verb, err)
	}
	recipients, err := ageio.LoadRecipients(a.keys)
	if err != nil {
		return e.fatal("%s: %v", verb, err)
	}
	in, err := ageInput(a.input)
	if err != nil {
		return e.fatal("%s: %v", verb, err)
	}
	defer in.close()
	encrypt := func(dst io.Writer) error {
		return ageio.Encrypt(dst, &ageReader{r: in, name: in.name}, recipients)
	}

	if a.output == "" {
		return ageToStdout(e, verb, in.name, encrypt)
	}
	if err := ageio.CheckOutput(a.output, in.file); err != nil {
		return e.fatal("%s: %v", verb, err)
	}
	stage, err := newAgeStage(a.output)
	if err != nil {
		return e.fatal("%s: %v", verb, err)
	}
	return agePublish(e, verb, in.name, stage, encrypt(&ageWriter{w: stage, name: a.output}))
}

// ageDecrypt is `xtar age-decrypt -i IDENTITY [-o OUTPUT] [INPUT]`.
func ageDecrypt(e *env, args []string) int {
	const verb = "age-decrypt"
	a, err := parseAgeIO(ageDecryptSpecs, "--identity-file", args)
	if err != nil {
		return e.fatal("%s: %v", verb, err)
	}
	identities, err := ageio.LoadIdentities(a.keys)
	if err != nil {
		return e.fatal("%s: %v", verb, err)
	}
	in, err := ageInput(a.input)
	if err != nil {
		return e.fatal("%s: %v", verb, err)
	}
	defer in.close()
	if a.output != "" {
		if err := ageio.CheckOutput(a.output, in.file); err != nil {
			return e.fatal("%s: %v", verb, err)
		}
	}

	// The header is parsed and every identity tried before any output
	// exists, so a wrong key or a non-age file fails having touched
	// nothing.  The payload is another matter: its last chunk
	// authenticates only at EOF.
	plain, err := ageio.DecryptReader(&ageReader{r: in, name: in.name}, identities)
	if err != nil {
		return e.fatal("%s: %v", verb, ageBlame(err, in.name))
	}
	if a.output == "" {
		return ageToStdout(e, verb, in.name, func(dst io.Writer) error {
			_, err := io.Copy(dst, plain)
			return err
		})
	}
	stage, err := newAgeStage(a.output)
	if err != nil {
		return e.fatal("%s: %v", verb, err)
	}
	_, err = io.Copy(&ageWriter{w: stage, name: a.output}, plain)
	return agePublish(e, verb, in.name, stage, err)
}

// ageToStdout runs a stream to standard output.  What was written
// before a failure stays written, and is said so: for a decryption
// that prefix is unauthenticated plaintext.
func ageToStdout(e *env, verb, inName string, stream func(io.Writer) error) int {
	out := &ageWriter{w: os.Stdout, name: "standard output"}
	if err := stream(out); err != nil {
		code := e.fatal("%s: %v", verb, ageBlame(err, inName))
		if out.n > 0 {
			e.warnf("%s: %s of incomplete output was already written to standard output and must be discarded",
				verb, humanBytes(out.n))
		}
		return code
	}
	return exitOK
}

// agePublish settles a file output once its stream has run: a clean
// run publishes the staged file, anything else discards it — neither
// a destination nor a temporary file is left behind.
func agePublish(e *env, verb, inName string, stage ageStage, err error) int {
	if err != nil {
		stage.Abort()
		return e.fatal("%s: %v", verb, ageBlame(err, inName))
	}
	if err := stage.Commit(); err != nil {
		stage.Abort()
		var published *ageio.PublishedError
		if errors.As(err, &published) {
			// The output is in place; only its durability is in doubt.
			e.warnf("%s: %v", verb, err)
			return exitWarn
		}
		return e.fatal("%s: %v", verb, err)
	}
	return exitOK
}

// ageReadError tags a failure of the input itself, so it is not
// blamed on the encryption.
type ageReadError struct {
	name string
	err  error
}

func (e *ageReadError) Error() string { return "read " + e.name + ": " + e.err.Error() }
func (e *ageReadError) Unwrap() error { return e.err }

// ageReader is an input whose read errors carry its name.
type ageReader struct {
	r    io.Reader
	name string
}

func (r *ageReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if err != nil && err != io.EOF {
		return n, &ageReadError{name: r.name, err: err}
	}
	return n, err
}

// ageWriteError tags a failure of the output itself, so it is not
// blamed on the input or the key.
type ageWriteError struct {
	name string
	err  error
}

func (e *ageWriteError) Error() string { return e.err.Error() }
func (e *ageWriteError) Unwrap() error { return e.err }

// ageWriter is an output that counts its bytes and names its errors.
type ageWriter struct {
	w    io.Writer
	name string
	n    int64
}

func (w *ageWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	w.n += int64(n)
	if err != nil {
		return n, &ageWriteError{name: w.name, err: err}
	}
	return n, nil
}

// ageBlame says which side of the pipe a stream error came from: the
// output that would not take it, or otherwise the input — a failed
// read, a malformed age file, a key that does not match, a chunk that
// does not authenticate.
func ageBlame(err error, inName string) error {
	var we *ageWriteError
	if errors.As(err, &we) {
		return fmt.Errorf("write %s: %w", we.name, we.err)
	}
	var re *ageReadError
	if errors.As(err, &re) {
		return err
	}
	return fmt.Errorf("%s: %w", inName, err)
}
