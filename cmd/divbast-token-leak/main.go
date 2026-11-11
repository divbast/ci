// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Command divbast-token-leak fails when an image archive holds the GitHub
// token its build was given.
//
// Usage:
//
//	divbast-token-leak ARCHIVE
//
// A repository that checks divbast/ci out at .ci runs it from its own root
// as .ci/bin/divbast-token-leak, once `just ci-tools` has built it:
//
//	GITHUB_TOKEN="${token}" .ci/bin/divbast-token-leak /tmp/image.tar
//
// ARCHIVE is the image as a tar, as docker image save or buildx's OCI
// exporter writes it. The token is read from GITHUB_TOKEN in the
// environment, so it stays off every command line, and is never printed.
//
// Every regular file in ARCHIVE is read without unpacking it, gzip and
// zstd layers decompressed, so the config, its history and any
// attestation are read too. The build should get the token only through a
// secret mount, which never reaches a layer. An ARG or ENV carrying it
// would, and the provenance records each build argument. zstd layers need
// the zstd command on PATH.
//
// Exit codes:
//
//	0  no file in ARCHIVE holds the token
//	1  a file holds it; stderr names each one
//	2  a file could not be read, ARCHIVE holds no files or cannot be read
//	   as a tar, or the command line or GITHUB_TOKEN is wrong
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
	"github.com/divbast/ci/internal/tokenleak"
)

const name = "divbast-token-leak"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Getenv, execx.OS{}, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, getenv func(string) string, zstd execx.Runner, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		// As for complain: nowhere better to report a failed write.
		_, _ = fmt.Fprintln(flags.Output(), "usage:", name, "ARCHIVE")
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 1 {
		complain(stderr, "want one ARCHIVE, not %d arguments", flags.NArg())
		flags.Usage()
		return 2
	}
	archive := flags.Arg(0)
	token := getenv("GITHUB_TOKEN")
	if token == "" {
		complain(stderr, "GITHUB_TOKEN is empty: it must hold the token the build was given")
		return 2
	}

	scanned, hits, err := tokenleak.Scan(ctx, archive, []byte(token), zstd)
	for _, hit := range hits {
		complain(stderr, "%s contains the GitHub token the build was given.", hit)
	}
	if err != nil {
		complain(stderr, "%v", err)
		return 2
	}
	if len(hits) > 0 {
		complain(stderr, "The token must reach the build only as a secret mount, never as an ARG or ENV.")
		return 1
	}
	if _, err = fmt.Fprintf(stdout, "no trace of the token in any of the %d files in %s\n", scanned, archive); err != nil {
		complain(stderr, "write the verdict: %v", err)
		return 1
	}
	return 0
}

// complain writes one line to stderr, after the command's name.
func complain(stderr io.Writer, format string, args ...any) {
	// A failed write to stderr leaves nowhere better to report it.
	_, _ = fmt.Fprintln(stderr, name+":", fmt.Sprintf(format, args...))
}
