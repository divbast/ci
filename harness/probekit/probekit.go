// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Package probekit writes a probe that divbast's harness runs inside a
// container: the core probe the contract's checks run, and any app's own
// probe beside it. A probe is a static binary on a read-only mount, so
// it needs nothing in the image, and is invoked as
//
//	<probe> <subcommand> [arguments]
//
// It prints one tab-separated record per assertion,
//
//	ok<TAB>what<TAB>expected<TAB>found
//	FAIL<TAB>what<TAB>expected<TAB>found
//
// except for a subcommand that prints what it read and asserts nothing,
// through [Output.Write].
//
// Its exit status is 0 when every record is ok; 1 when any is FAIL, and a
// subcommand that returns an error is recorded as one, as is a record
// that could not be written; and 2 for a subcommand or arguments it does
// not know.
//
// An app's probe is a main package of the app's own module that hands its
// subcommands to [Main]:
//
//	func main() {
//		os.Exit(probekit.Main(context.Background(), map[string]probekit.Command{
//			"assert-page": {Run: assertPage},
//		}, os.Args[1:], os.Stdout, os.Stderr))
//	}
package probekit

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
)

// Output is where a subcommand writes its records. It counts the failed
// ones, and keeps the first write that failed, so [Main] exits as the
// records say, and never 0 for records that never reached the harness.
type Output struct {
	w        io.Writer
	failures int
	err      error
}

// Record writes one record: ok or FAIL as ok says, what was checked, what
// was expected and what was found. A tab, a newline or a carriage return
// in any field becomes a space, since they separate records and fields,
// and each field is trimmed.
func (o *Output) Record(ok bool, what, expected, found string) {
	status := "ok"
	if !ok {
		status = "FAIL"
		o.failures++
	}
	_, _ = fmt.Fprintf(o, "%s\t%s\t%s\t%s\n", status, oneLine(what), oneLine(expected), oneLine(found))
}

// Equal records whether found is exactly expected.
func (o *Output) Equal(what, expected, found string) {
	o.Record(found == expected, what, expected, found)
}

// Write writes p as it is, for a subcommand that prints what it read
// rather than records. A write that fails makes [Main] exit 1.
func (o *Output) Write(p []byte) (int, error) {
	if o.err != nil {
		return 0, o.err
	}
	n, err := o.w.Write(p)
	if err != nil {
		o.err = err
	}
	return n, err
}

// separators turns what separates records and fields into spaces.
var separators = strings.NewReplacer("\t", " ", "\n", " ", "\r", " ")

// oneLine is text as one field of a record, trimmed of what PHP's trim
// takes off, as the PHP probe's records are.
func oneLine(text string) string {
	return strings.Trim(separators.Replace(text), " \t\n\r\x00\x0b")
}

// Command is one subcommand: the arguments it takes, named for its usage
// line, and what runs it.
type Command struct {
	// Args names the arguments, in order. A Variadic command takes one or
	// more in place of its last, or any number when Args is empty.
	Args     []string
	Variadic bool
	// Run runs the subcommand with its arguments. A returned error is
	// recorded as a failure: "<name> completed", expecting no exception.
	Run func(ctx context.Context, out *Output, args []string) error
}

// accepts reports whether c takes n arguments.
func (c Command) accepts(n int) bool {
	if c.Variadic {
		return n >= len(c.Args)
	}
	return n == len(c.Args)
}

// synopsis returns c's arguments as its usage line names them.
func (c Command) synopsis() string {
	words := make([]string, len(c.Args))
	for i, a := range c.Args {
		words[i] = "<" + a + ">"
	}
	if c.Variadic {
		if len(words) == 0 {
			return "[arguments...]"
		}
		words[len(words)-1] += "..."
	}
	return strings.Join(words, " ")
}

// Main runs the subcommand args names, from commands, with the rest of
// args, writing its records to stdout, and returns the exit status the
// package comment gives. A subcommand or arguments it does not know are
// said on stderr, with the usage.
func Main(ctx context.Context, commands map[string]Command, args []string, stdout, stderr io.Writer) int {
	name := ""
	if len(args) > 0 {
		name = args[0]
	}
	c, ok := commands[name]
	if !ok {
		if name == "" {
			_, _ = fmt.Fprintln(stderr, "no subcommand given")
		} else {
			_, _ = fmt.Fprintf(stderr, "unknown subcommand '%s'\n", name)
		}
		_, _ = io.WriteString(stderr, usage(commands))
		return 2
	}
	operands := args[1:]
	if !c.accepts(len(operands)) {
		_, _ = fmt.Fprintf(stderr, "%s takes %s, got %d\n", name, cmp.Or(c.synopsis(), "no arguments"), len(operands))
		return 2
	}

	out := &Output{w: stdout}
	if err := c.Run(ctx, out, operands); err != nil {
		out.Record(false, name+" completed", "no exception", err.Error())
	}
	if out.err != nil {
		_, _ = fmt.Fprintf(stderr, "writing the records of %s: %v\n", name, out.err)
		return 1
	}
	if out.failures > 0 {
		return 1
	}
	return 0
}

// usage lists every subcommand with its arguments, by name.
func usage(commands map[string]Command) string {
	var b strings.Builder
	b.WriteString("usage: <probe> <subcommand> [arguments]\n\nsubcommands:\n")
	for _, name := range slices.Sorted(maps.Keys(commands)) {
		b.WriteString(strings.TrimRight("  "+name+" "+commands[name].synopsis(), " ") + "\n")
	}
	return b.String()
}
