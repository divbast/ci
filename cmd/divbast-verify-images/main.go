// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Command divbast-verify-images refuses a Containerfile that builds from
// an image not pinned by digest, or from one whose publisher signs it
// that its publisher did not.
//
// Usage:
//
//	divbast-verify-images [-containerfile Containerfile]
//
// A repository that checks divbast/ci out at .ci runs it from its own root
// as .ci/bin/divbast-verify-images, once `just ci-tools` has built it.
//
// It reads every image the Containerfile's FROM, COPY --from= and RUN
// --mount from= take, a FROM's build argument resolved to its default,
// and the frontend a # syntax= directive names, which BuildKit runs as
// the build itself. Each must be <name>:<tag>@sha256:<digest>, written
// out in full, so that Renovate can move it; a tag without a digest, a
// COPY --from= built from a variable, or a FROM built from a build
// argument with no default, or from one that names another, is refused.
// A registry is read as it serves an image, its host in lower case and
// without :443. Then each image in its table is verified:
//
//	ghcr.io/divbast/{frankenphp,unrar,ffmpeg,mediainfo}, by their
//	attestation, each digest once (frankenphp may be named only once):
//	  gh attestation verify oci://ghcr.io/divbast/<image>@sha256:<digest> \
//	      --repo <repo> --signer-workflow <workflow> \
//	      --source-ref refs/heads/main
//	where <repo> and <workflow> are, by image:
//	  frankenphp: divbast/frankenphp and
//	    divbast/frankenphp/.github/workflows/build.yml@refs/heads/main
//	  unrar, ffmpeg, mediainfo: divbast/native-tools and
//	    divbast/native-tools/.github/workflows/build.yml@refs/heads/main
//	gcr.io/distroless/*, by its signature:
//	  cosign verify gcr.io/distroless/<image>@sha256:<digest> \
//	      --certificate-identity keyless@distroless.iam.gserviceaccount.com \
//	      --certificate-oidc-issuer https://accounts.google.com
//	dhi.io/*, by Docker's key, dhi-2.pub, which the command embeds:
//	  cosign verify --key dhi-2.pub --experimental-oci11 \
//	      dhi.io/<image>:<tag>@sha256:<digest>
//
// A divbast image the table does not name is refused, and an image in it
// may stand only in a FROM, a COPY --from= or a build argument a FROM
// uses. Any other image passes once it is pinned.
//
// gh must be 2.102.0 or newer and have a token that can read attestations:
// in a workflow, GH_TOKEN with attestations: read. cosign needs no token.
// Both run with DOCKER_CONFIG pointing at an empty directory the command
// makes and then removes, since each would otherwise send whatever
// registry login Docker's configuration holds, and a stale one is refused
// even for a public image.
//
// dhi.io answers nothing without a login, so a Containerfile that names a
// dhi.io image needs DHI_USERNAME and DHI_TOKEN, a Docker ID and its
// personal access token. They are written, for dhi.io alone, to that
// directory's config.json, beside dhi-2.pub, and only when a dhi.io image
// is named. The key is the one committed to the command, never fetched.
//
// It prints "verified: <image>" for each image in the table, and
// "pinned: <image>" for each other.
//
// Exit codes:
//
//	0  every image is pinned, and every one in the table verified
//	1  one is not, or that could not be told: the Containerfile cannot be
//	   read, names an image unpinned or where it may not, gh is too old,
//	   a dhi.io image is named with no DHI_USERNAME and DHI_TOKEN, or a
//	   verification failed; stderr says which, with the tool's own report
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
	"slices"
	"syscall"

	"github.com/divbast/ci/internal/execx"
	"github.com/divbast/ci/internal/verify"
)

const name = "divbast-verify-images"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	tools := func(env []string) execx.Runner { return execx.OS{Env: env} }
	code := run(ctx, os.Args[1:], os.Getenv, tools, os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// run is the command. getenv reads its environment. tools returns the
// runner for gh and cosign, given the environment entries every one of
// their commands must get on top of the caller's.
func run(ctx context.Context, args []string, getenv func(string) string, tools func(env []string) execx.Runner, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	containerfile := flags.String("containerfile", "Containerfile", "the Containerfile `FILE` to check")
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

	refs, err := read(*containerfile)
	if err != nil {
		complain(stderr, "%s: %v", *containerfile, err)
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

	var dhiKey string
	if verify.NeedsDHI(refs) {
		if err = verify.WriteDockerConfig(dockerConfig, getenv("DHI_USERNAME"), getenv("DHI_TOKEN")); err != nil {
			complain(stderr, "%s: %v", *containerfile, err)
			return 1
		}
		if dhiKey, err = verify.WriteDHIKey(dockerConfig); err != nil {
			complain(stderr, "write dhi-2.pub: %v", err)
			return 1
		}
	}

	r := tools([]string{"DOCKER_CONFIG=" + dockerConfig})
	if err = verify.Verify(ctx, verify.Tools{GH: r, Cosign: r, DHIKey: dhiKey}, refs, stderr); err != nil {
		complain(stderr, "%s: %v", *containerfile, err)
		return 1
	}
	var said []string
	for _, ref := range refs {
		if slices.Contains(said, ref.String()) {
			continue
		}
		said = append(said, ref.String())
		verdict := "pinned"
		if verify.Listed(ref) {
			verdict = "verified"
		}
		if _, err = fmt.Fprintf(stdout, "%s: %s\n", verdict, ref); err != nil {
			complain(stderr, "write the verdict: %v", err)
			return 1
		}
	}
	return 0
}

// read reads the Containerfile at path, through an [os.Root] on its
// directory, and returns the images it builds from.
func read(path string) (refs []verify.Ref, err error) {
	dir, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, dir.Close()) }()
	f, err := dir.Open(filepath.Base(path))
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	return verify.Refs(f)
}

// complain writes one line to stderr, after the command's name.
func complain(stderr io.Writer, format string, args ...any) {
	// A failed write to stderr leaves nowhere better to report it.
	_, _ = fmt.Fprintln(stderr, name+":", fmt.Sprintf(format, args...))
}
