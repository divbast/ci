// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Command divbast-testcount fails a go test run in which no test ran, or
// one skipped.
//
// Usage:
//
//	go test -json ./... | divbast-testcount
//
// A repository that checks divbast/ci out at .ci runs it from its own root
// as .ci/bin/divbast-testcount, once `just ci-tools` has built it. app.just's
// acceptance recipe pipes the acceptance suite through it.
//
// go test exits 0 when every test skipped, and prints only ok, so a suite
// that never ran reads in a log as one that passed. This reads go test
// -json's events on stdin and writes each one's output to stdout as it
// comes, so the log reads as go test -v's would and names every test, then
// one summary line:
//
//	divbast-testcount: <P> passed, <S> skipped, <F> failed in <K> package(s)
//
// Tests and subtests count alike. A run passes only when at least one test
// passed, none failed or skipped, no package failed to build, and every
// package the stream names ended in pass.
//
// Exit codes:
//
//	0  the run passed
//	1  it did not: a test failed or skipped, a package failed, did not
//	   build, ran no tests or never finished, or no test passed; stderr
//	   names each test and package. Or a write failed
//	2  stdin could not be read, a line of it is not a go test -json
//	   event, it holds no events at all, or the command line is wrong
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/divbast/ci/internal/testcount"
)

const name = "divbast-testcount"

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		// As for complain: nowhere better to report a failed write.
		_, _ = fmt.Fprintln(flags.Output(), "usage: go test -json ./... |", name)
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() > 0 {
		complain(stderr, "unexpected argument %q: the events come on stdin", flags.Arg(0))
		flags.Usage()
		return 2
	}

	res, err := testcount.Count(stdin, stdout, stderr)
	if err != nil {
		complain(stderr, "%v", err)
	}
	return testcount.Code(res, err)
}

// complain writes one line to stderr, after the command's name.
func complain(stderr io.Writer, format string, args ...any) {
	// A failed write to stderr leaves nowhere better to report it.
	_, _ = fmt.Fprintln(stderr, name+":", fmt.Sprintf(format, args...))
}
