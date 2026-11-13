// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Command divbast-verify-frankenphp refuses a FrankenPHP binary that
// divbast/frankenphp's main build did not attest.
//
// Usage:
//
//	divbast-verify-frankenphp [-containerfile Containerfile]
//
// A repository that checks divbast/ci out at .ci runs it from its own root
// as .ci/bin/divbast-verify-frankenphp, once `just ci-tools` has built it.
//
// It finds the one COPY --from=ghcr.io/divbast/frankenphp:<tag>@sha256:<digest>
// in the Containerfile, and has gh check the digest's attestation:
//
//	gh attestation verify oci://ghcr.io/divbast/frankenphp@sha256:<digest> \
//	    --repo divbast/frankenphp \
//	    --signer-workflow divbast/frankenphp/.github/workflows/build.yml@refs/heads/main \
//	    --source-ref refs/heads/main
//
// So a digest passes only when frankenphp's build workflow made it from
// main: not a pull request's build, not another repository's image. The
// image must be named once, written out in full, so that Renovate can move
// it; a tag without a digest, a --from= built from a variable, or one
// that takes from a stage whose image holds an unresolved build argument,
// is refused.
//
// gh must be 2.102.0 or newer and have a token that can read attestations:
// in a workflow, GH_TOKEN with attestations: read. It runs with
// DOCKER_CONFIG pointing at an empty directory the command makes and then
// removes, since gh would otherwise send whatever registry login Docker's
// configuration holds, and a stale one is refused even for a public image.
//
// Exit codes:
//
//	0  the binary is attested by divbast/frankenphp's main build
//	1  it is not, or that could not be told: the Containerfile names the
//	   image other than once in full, it cannot be read, gh is too old or
//	   failed, or no attestation from that build matches; stderr says
//	   which, with gh's own report
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
	"path/filepath"
	"syscall"

	"github.com/divbast/ci/internal/execx"
	"github.com/divbast/ci/internal/frankenphpref"
)

const name = "divbast-verify-frankenphp"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	gh := func(env []string) execx.Runner { return execx.OS{Env: env} }
	code := run(ctx, os.Args[1:], gh, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// run is the command. gh returns the runner for gh, given the environment
// entries every gh command must get on top of the caller's.
func run(ctx context.Context, args []string, gh func(env []string) execx.Runner, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	containerfile := flags.String("containerfile", "Containerfile", "the Containerfile `FILE` that takes the binary")
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

	ref, err := find(*containerfile)
	if err != nil {
		complain(stderr, "%s: %v", *containerfile, err)
		return 1
	}
	if _, err = fmt.Fprintln(stdout, "verifying", ref); err != nil {
		complain(stderr, "write the reference: %v", err)
		return 1
	}

	dockerConfig, err := os.MkdirTemp("", name+"-")
	if err != nil {
		complain(stderr, "make an empty Docker configuration: %v", err)
		return 1
	}
	// A directory left behind is empty and holds no secret, so it is
	// reported without changing the verdict.
	defer func() {
		if rerr := os.RemoveAll(dockerConfig); rerr != nil {
			complain(stderr, "remove %s: %v", dockerConfig, rerr)
		}
	}()

	if err = frankenphpref.Verify(ctx, gh([]string{"DOCKER_CONFIG=" + dockerConfig}), ref, stderr); err != nil {
		complain(stderr, "%s: %v", ref, err)
		return 1
	}
	if _, err = fmt.Fprintln(stdout, "verified: divbast/frankenphp's main build attested", ref.Image()); err != nil {
		complain(stderr, "write the verdict: %v", err)
		return 1
	}
	return 0
}

// find reads the Containerfile at path, through an [os.Root] on its
// directory, and finds the binary it takes.
func find(path string) (ref frankenphpref.Ref, err error) {
	dir, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return frankenphpref.Ref{}, err
	}
	defer func() { err = errors.Join(err, dir.Close()) }()
	f, err := dir.Open(filepath.Base(path))
	if err != nil {
		return frankenphpref.Ref{}, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	return frankenphpref.Find(f)
}

// complain writes one line to stderr, after the command's name.
func complain(stderr io.Writer, format string, args ...any) {
	// A failed write to stderr leaves nowhere better to report it.
	_, _ = fmt.Fprintln(stderr, name+":", fmt.Sprintf(format, args...))
}
