// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Command divbast-pin prints the divbast/ci commit a repository's
// workflows pin, and fails unless they all pin the same one.
//
// Usage:
//
//	divbast-pin [-dir .github/workflows] [-expect SHA]
//
// With -expect, it also fails unless that commit is SHA. A reusable
// workflow passes its own job.workflow_sha there, so a caller whose other
// workflows pin a different commit fails its own CI. An empty SHA is a
// wrong command line, not a missing -expect: it comes from an expression
// or a command that produced nothing, and taken as no -expect it would
// check nothing.
//
// Exit codes:
//
//	0  the workflows pin one commit, printed on stdout, and it is SHA
//	   when -expect is given; or -h or -help asked for the usage, which
//	   goes to stderr
//	1  no workflow pins divbast/ci to a commit, they pin more than one,
//	   the pin is not SHA, or the directory cannot be read; stderr says
//	   which, naming every ref found
//	2  the command line is wrong, an empty -expect among it
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/divbast/ci/internal/pin"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("divbast-pin", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dir := flags.String("dir", ".github/workflows", "the `directory` holding the workflows")
	var expect string
	flags.Func("expect", "fail unless the workflows pin this `SHA`", func(sha string) error {
		if sha == "" {
			return errors.New("an empty SHA would check nothing")
		}
		expect = sha
		return nil
	})
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() > 0 {
		complain(stderr, "unexpected argument %q", flags.Arg(0))
		flags.Usage()
		return 2
	}

	sha, err := find(*dir)
	if err != nil {
		complain(stderr, "%v", err)
		return 1
	}
	if expect != "" && sha != expect {
		complain(stderr, "the workflows in %s pin divbast/ci at %s, not %s", *dir, sha, expect)
		return 1
	}
	if _, err = fmt.Fprintln(stdout, sha); err != nil {
		complain(stderr, "write the pin: %v", err)
		return 1
	}
	return 0
}

func find(dir string) (sha string, err error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", fmt.Errorf("open workflows: %w", err)
	}
	defer func() {
		if cerr := root.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("close workflows: %w", cerr)
		}
	}()
	return pin.FromWorkflows(root)
}

// complain writes one line to stderr, after the command's name.
func complain(stderr io.Writer, format string, args ...any) {
	// A failed write to stderr leaves nowhere better to report it.
	_, _ = fmt.Fprintln(stderr, "divbast-pin:", fmt.Sprintf(format, args...))
}
