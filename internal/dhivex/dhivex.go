// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Package dhivex fetches the OpenVEX document Docker publishes for a
// Hardened Image, and verifies it against Docker's key before a scan may
// apply it.
//
// Trivy reads a Docker Hardened Image's Debian packages, Docker's own
// builds versioned …+dhiN, as Debian's, and reports every vulnerability
// Debian has not fixed in them. Docker states, in a document per image,
// which of those its builds are not affected by, keyed by package URL, so
// the statements hold in an image built on one. It publishes them in
// github.com/docker-hardened-images/advisories, each with a Sigstore
// bundle that signs it with the key divbast-verify-images verifies the
// images themselves with:
//
//	vex/<name>/dhi-<name>.vex.json
//	vex/<name>/dhi-<name>.vex.json.sig
//
// A scan applies only the document of the image its final stage builds
// on, [verify.Base], the one whose packages ship. A document is Docker's
// assessment of its own image, and some of its statements name a package
// with no version, so a build stage's document, applied to the runtime,
// would answer for packages Docker never assessed there.
//
// Documents are read from main, not a pinned commit: the signature is the
// trust, and a pin would need a person or a Renovate rule to move it.
package dhivex

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/divbast/ci/internal/execx"
	"github.com/divbast/ci/internal/verify"
)

// Advisories is the URL the documents are under, as
// raw.githubusercontent.com serves the advisories repository's main
// branch to anyone, with no token.
const Advisories = "https://raw.githubusercontent.com/docker-hardened-images/advisories/main/vex/"

const (
	// maxSize is the most a fetch reads of one file.
	// dhi-golang.vex.json, the largest in November 2026, is 5.4 MB.
	maxSize = 64 << 20
	// tries is how many times a fetch is tried while each try fails in a
	// way trying again could fix.
	tries = 3
	// perTry bounds each try, its body included.
	perTry = time.Minute
	// firstPause is the pause before the second try, doubled before each
	// try after it.
	firstPause = 2 * time.Second
)

var (
	// ErrName means a dhi.io image's name is not one path segment, as
	// every image Docker publishes is, so names no document.
	ErrName = errors.New("a dhi.io image's name is not one path segment, so no document in DHI's advisories is its")
	// ErrFetch means a document or its bundle could not be fetched.
	ErrFetch = errors.New("could not fetch")
	// ErrNotVerified means cosign did not verify a document against
	// dhi-2.pub, or could not tell.
	ErrNotVerified = errors.New("not verified against dhi-2.pub")
)

// segment is one path segment of an image's name, as the OCI distribution
// spec allows one.
var segment = regexp.MustCompile(`^[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*$`)

// cosignWithin bounds a verification. cosign may fetch Sigstore's trusted
// root before it can verify, and one that hangs must not hold the scan
// until the job's own time limit.
const cosignWithin = 2 * time.Minute

// Name returns the name of the dhi.io image r is, aspnetcore for
// dhi.io/aspnetcore, and whether it is one. The error wraps [ErrName],
// and names r's line.
func Name(r verify.Ref) (name string, ok bool, err error) {
	if !verify.IsDHI(r) {
		return "", false, nil
	}
	name = r.Name[len(verify.DHI):]
	if !segment.MatchString(name) {
		return "", false, fmt.Errorf("%w: line %d has %s", ErrName, r.Line, r)
	}
	return name, true, nil
}

// Source is where [Documents] fetches from.
type Source struct {
	// Client sends each request; nil means [http.DefaultClient]. Each try
	// is bounded however the client is set.
	Client *http.Client
	// Base is the URL the documents are under, ending in a slash; empty
	// means [Advisories].
	Base string
}

// Verifier verifies a document with cosign, against Docker's key.
type Verifier struct {
	// Cosign runs cosign.
	Cosign execx.Runner
	// Key is the path to a file holding [verify.DHIPublicKey], as
	// [verify.WriteDHIKey] writes it.
	Key string
	// Log is where cosign's report goes, its stderr and then its stdout.
	// Nil drops it.
	Log io.Writer
}

// Document fetches the document of dhi.io/<name>, and its bundle, from
// src into dir, verifies the one with the other with v, and returns the
// document's path. Any failure returns "" and an error that names the
// image, wrapping [ErrName], [ErrFetch] or [ErrNotVerified] where one
// applies, or the error the last try failed with.
//
// A fetch is tried again, up to three tries in all, while a try gets no
// answer, takes over a minute, or is answered 429 or 5xx. Any other
// answer but 200 is final, and so is a file over 64 MiB.
func Document(ctx context.Context, src Source, v Verifier, dir, name string) (string, error) {
	path, err := document(ctx, src, v, dir, name)
	if err != nil {
		return "", fmt.Errorf("%s%s: %w", verify.DHI, name, err)
	}
	return path, nil
}

// document is [Document], with errors that do not name the image.
func document(ctx context.Context, src Source, v Verifier, dir, name string) (string, error) {
	if v.Key == "" {
		return "", errors.New("no path to dhi-2.pub, the key that verifies DHI's VEX documents")
	}
	if !segment.MatchString(name) {
		return "", fmt.Errorf("%w: %q", ErrName, name)
	}
	file := "dhi-" + name + ".vex.json"
	under := cmp.Or(src.Base, Advisories) + name + "/"
	for _, f := range []string{file, file + ".sig"} {
		data, err := fetch(ctx, cmp.Or(src.Client, http.DefaultClient), under+f)
		if err != nil {
			return "", err
		}
		if err := write(dir, f, data); err != nil {
			return "", err
		}
	}
	doc := filepath.Join(dir, file)
	if err := v.verify(ctx, doc); err != nil {
		return "", err
	}
	return doc, nil
}

// fetch returns the body of url, trying again while a try fails in a way
// that trying again could fix.
func fetch(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	pause := firstPause
	for try := 1; ; try++ {
		data, again, err := fetchOnce(ctx, client, url)
		switch {
		case err == nil:
			return data, nil
		case !again:
			return nil, err
		case try == tries:
			return nil, fmt.Errorf("%w, %d times", err, tries)
		}
		if err := wait(ctx, pause); err != nil {
			return nil, err
		}
		pause *= 2
	}
}

// fetchOnce tries url once, and says whether a failure is one that
// trying again could fix: no answer, a try that ran past perTry, or 429
// or 5xx. A try the caller's own context ended is said to be one too,
// since the pause before the next try then ends at once with the
// caller's error.
func fetchOnce(ctx context.Context, client *http.Client, url string) (data []byte, again bool, err error) {
	tryCtx, cancel := context.WithTimeout(ctx, perTry)
	defer cancel()
	req, err := http.NewRequestWithContext(tryCtx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, true, fmt.Errorf("%w %s: %w", ErrFetch, url, err)
	}
	defer func() { err = errors.Join(err, resp.Body.Close()) }()
	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return nil, true, fmt.Errorf("%w %s: it answered %s", ErrFetch, url, resp.Status)
	default:
		return nil, false, fmt.Errorf("%w %s: it answered %s", ErrFetch, url, resp.Status)
	}
	data, err = io.ReadAll(io.LimitReader(resp.Body, maxSize+1))
	switch {
	case err != nil:
		return nil, true, fmt.Errorf("%w %s: %w", ErrFetch, url, err)
	case len(data) > maxSize:
		return nil, false, fmt.Errorf("%w %s: it is over %d MiB, the most read of one file", ErrFetch, url, maxSize>>20)
	}
	return data, false, nil
}

// wait waits for d, or until ctx is done, whichever comes first, and
// returns ctx's error if ctx ended the wait.
func wait(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// write writes data to the file name in dir, readable by its owner alone.
func write(dir, name string, data []byte) (err error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	return root.WriteFile(name, data, 0o600)
}

// verify asks cosign whether Docker signed the document at doc, with the
// bundle beside it, with the key at v.Key, and passes on what it said.
// Any status but 0 is a refusal, and so is a cosign that could not start,
// or ran past cosignWithin, whose Result holds no status at all.
func (v Verifier) verify(ctx context.Context, doc string) error {
	ctx, cancel := context.WithTimeout(ctx, cosignWithin)
	defer cancel()
	res, err := v.Cosign.Run(ctx, "cosign", "verify-blob", "--key", v.Key, "--bundle", doc+".sig", doc)
	if err != nil {
		return fmt.Errorf("cosign verify-blob: %w", err)
	}
	if v.Log != nil {
		if _, err = v.Log.Write(res.Stderr); err == nil {
			_, err = v.Log.Write(res.Stdout)
		}
		if err != nil {
			return fmt.Errorf("write cosign's report: %w", err)
		}
	}
	if res.Code != 0 {
		return fmt.Errorf("%s %w: cosign verify-blob exited %d", filepath.Base(doc), ErrNotVerified, res.Code)
	}
	return nil
}
