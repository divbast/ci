// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Command divbast-published-revision prints the commit a published image
// was built from, read off the org.opencontainers.image.revision
// annotation on its index.
//
// Usage:
//
//	divbast-published-revision IMAGE
//
// IMAGE is a ghcr.io reference, such as ghcr.io/divbast/librespeed:latest,
// and skopeo reads it as an anonymous client, as users pull. When the
// registry refuses to show it, gh asks the GitHub API whether the package
// is absent or private, which needs a token that can read the
// organisation's packages: in a workflow, GH_TOKEN with packages: read.
//
// Exit codes:
//
//	0  the revision is on stdout, or stdout is empty because nothing is
//	   published as IMAGE yet, which stderr says
//	1  the package is private, or the revision could not be read: the
//	   registry or the API failed to answer, the token cannot read the
//	   package, or the image carries no revision; stderr says which
//	2  the command line is wrong
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/divbast/ci/internal/execx"
	"github.com/divbast/ci/internal/ghapi"
	"github.com/divbast/ci/internal/registry"
)

const name = "divbast-published-revision"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], execx.OS{}, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, r execx.Runner, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		// As for complain: nowhere better to report a failed write.
		_, _ = fmt.Fprintln(flags.Output(), "usage:", name, "IMAGE")
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 1 {
		complain(stderr, "want one IMAGE, not %d arguments", flags.NArg())
		flags.Usage()
		return 2
	}
	image := flags.Arg(0)

	lookup := registry.Lookup{Run: r, GH: ghapi.Client{Run: r}}
	revision, state, err := lookup.Revision(ctx, image)
	if err != nil {
		complain(stderr, "%v", err)
		return 1
	}
	if state == registry.Absent {
		complain(stderr, "nothing is published as %s yet", image)
		return 0
	}
	if _, err = fmt.Fprintln(stdout, revision); err != nil {
		complain(stderr, "write the revision: %v", err)
		return 1
	}
	return 0
}

// complain writes one line to stderr, after the command's name.
func complain(stderr io.Writer, format string, args ...any) {
	// A failed write to stderr leaves nowhere better to report it.
	_, _ = fmt.Fprintln(stderr, name+":", fmt.Sprintf(format, args...))
}
