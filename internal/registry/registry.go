// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Package registry reads which commit a published image was built from,
// off the org.opencontainers.image.revision annotation publishing writes
// on its index.
//
// It reads as an anonymous client, as users pull, and tells three answers
// apart: published, with the revision; absent, because nothing is
// published there yet; and anything else, an error. A revision that cannot
// be read is never taken for one that is absent. Absent is what lets a
// first publish through without a commit to compare with, and so what
// would let a registry outage move :latest backwards. Presence tells the
// same answers apart without the revision, for a caller that needs only
// whether anything is published.
package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/divbast/ci/internal/execx"
	"github.com/divbast/ci/internal/ghapi"
)

// State is what a registry says about an image reference. The zero State
// is neither: it goes with an error.
type State int

const (
	// Absent means nothing is published under the reference yet: no such
	// package, or no such tag in a public one.
	Absent State = iota + 1
	// Published means the reference resolves for an anonymous client.
	// Revision also requires it to name the commit it was built from.
	Published
)

// String returns "absent" or "published".
func (s State) String() string {
	switch s {
	case Absent:
		return "absent"
	case Published:
		return "published"
	default:
		return fmt.Sprintf("State(%d)", int(s))
	}
}

// ErrPrivate means the package exists but is not public, so an anonymous
// client cannot read it, and no user can pull it.
var ErrPrivate = errors.New("package is private")

// ErrRefused means the registry refused to show an image to an anonymous
// client, and a RegistryOnly Lookup asked GitHub nothing about why. That
// can mean nothing is published there, a private package, or a registry
// failing to serve a public one: only the GitHub API tells them apart.
var ErrRefused = errors.New("refused, and GitHub not asked why")

// host is the one registry Lookup reads. The GitHub API, which tells an
// absent package from a private one, knows about no other.
const host = "ghcr.io"

// timeout is how long the skopeo call may take when a Lookup sets no
// Timeout of its own.
const timeout = time.Minute

// notFound is GitHub's message for a package that does not exist, which
// alone among 404s says nothing is published there.
const notFound = "Package not found."

// annotation is the index annotation that names the commit.
const annotation = "org.opencontainers.image.revision"

var commit = regexp.MustCompile(`^[0-9a-f]{40}$`)

// refusals are what skopeo prints when the registry declines to show an
// image, as opposed to failing to answer: a tag or repository it does not
// have, a read it refuses, and the 403 ghcr.io gives an anonymous token
// request for a package that is missing or private. Which of those it is,
// only the GitHub API can say.
var refusals = [][]byte{
	[]byte("manifest unknown"),
	[]byte("name unknown"),
	[]byte("denied"),
	[]byte("unauthorized"),
	[]byte("Requesting bearer token: received unexpected HTTP status: 403 Forbidden"),
}

// Lookup reads published revisions with skopeo, and asks the GitHub API,
// through gh, about a package the registry refuses to show.
type Lookup struct {
	Run execx.Runner
	GH  ghapi.Client
	// Timeout bounds the skopeo call, as GH's own bounds each gh call, so
	// that a registry that never answers fails the lookup rather than
	// holding the job until the job's own timeout. Zero means a minute.
	Timeout time.Duration
	// RegistryOnly, when set, never asks the GitHub API, for a caller with
	// no token that may read packages: a refusal is then an error wrapping
	// [ErrRefused], never an answer.
	RegistryOnly bool
}

// Revision returns the commit image, a ghcr.io reference such as
// ghcr.io/divbast/librespeed:latest, was built from, with [Published].
//
// It returns "" and [Absent] when nothing is published there yet: the
// registry refuses to show the image, and the GitHub API says the package
// is not found, or that it is public and only this tag is missing. The
// package's owner must be an organisation, and GH's token able to read
// its packages (packages: read).
//
// Anything else is an error, with the zero State: a private package
// (wrapping [ErrPrivate]), a refusal a RegistryOnly Lookup did not ask
// about (wrapping [ErrRefused]), a registry or API that fails to answer or
// takes longer than its timeout, a 404 that does not say the package is
// not found, a token the API refuses, and an image with no full commit SHA
// in its revision annotation.
func (l Lookup) Revision(ctx context.Context, image string) (string, State, error) {
	manifest, state, err := l.inspect(ctx, image)
	if err != nil || state != Published {
		return "", state, err
	}
	var index struct {
		Annotations map[string]string `json:"annotations"`
	}
	if err = json.Unmarshal(manifest, &index); err != nil {
		return "", 0, unreadable(image, fmt.Errorf("its manifest is not JSON: %w", err))
	}
	revision := index.Annotations[annotation]
	if !commit.MatchString(revision) {
		return "", 0, fmt.Errorf("%s carries no revision annotation, only '%s', so nothing says which commit it was built from", image, revision)
	}
	return revision, Published, nil
}

// Presence says whether image, a ghcr.io reference, is published, decided
// as [Lookup.Revision] decides it, but asking nothing of the image itself:
// [Published] when an anonymous client can read it, as users pull it, and
// [Absent] when nothing is published there yet. Anything else is an error,
// with the zero State, as Revision's are.
func (l Lookup) Presence(ctx context.Context, image string) (State, error) {
	_, state, err := l.inspect(ctx, image)
	return state, err
}

// inspect reads image's manifest as an anonymous client, and returns it
// with [Published]. When the registry refuses to show image, it returns
// [Absent] or an error, as the GitHub API says, or, for a RegistryOnly
// Lookup, an error wrapping [ErrRefused].
func (l Lookup) inspect(ctx context.Context, image string) ([]byte, State, error) {
	owner, name, err := parse(image)
	if err != nil {
		return nil, 0, err
	}

	limit := l.Timeout
	if limit == 0 {
		limit = timeout
	}
	inspectCtx, cancel := context.WithTimeout(ctx, limit)
	res, err := l.Run.Run(inspectCtx, "skopeo", "inspect", "--raw", "--no-creds", "docker://"+image)
	timedOut := ctx.Err() == nil && errors.Is(inspectCtx.Err(), context.DeadlineExceeded)
	cancel()
	if err != nil {
		// Only the Lookup's own limit is the Lookup's to name: a deadline
		// of the caller's, reached first, is the caller's to report.
		if timedOut {
			err = fmt.Errorf("skopeo inspect docker://%s gave up after %v: %w", image, limit, err)
		}
		return nil, 0, unreadable(image, err)
	}
	if res.Code == 0 {
		return res.Stdout, Published, nil
	}
	stderr := bytes.TrimSpace(res.Stderr)
	if !slices.ContainsFunc(refusals, func(r []byte) bool { return bytes.Contains(stderr, r) }) {
		return nil, 0, unreadable(image, fmt.Errorf("skopeo exit status %d: %s", res.Code, stderr))
	}
	if l.RegistryOnly {
		return nil, 0, fmt.Errorf("%w: %s refused to show %s: %s", ErrRefused, host, image, stderr)
	}
	state, err := l.refused(ctx, image, owner, name, stderr)
	return nil, state, err
}

// refused decides, from the GitHub API, what a registry's refusal to show
// image means. stderr is what skopeo said.
func (l Lookup) refused(ctx context.Context, image, owner, name string, stderr []byte) (State, error) {
	pkg := host + "/" + owner + "/" + name
	var p struct {
		Visibility string `json:"visibility"`
	}
	resp, err := l.GH.Get(ctx, "orgs/"+url.PathEscape(owner)+"/packages/container/"+url.PathEscape(name), &p)
	if err != nil {
		return 0, fmt.Errorf("%s refused to show %s, and the GitHub API could not say whether it is absent or private: %w", host, image, err)
	}

	switch resp.Status {
	case 404:
		if resp.Message != notFound {
			return 0, fmt.Errorf("%s refused to show %s, and GitHub answered HTTP 404 for package %s with %q, not %q, so nothing says it is absent",
				host, image, pkg, resp.Message, notFound)
		}
		return Absent, nil
	case 200:
		switch p.Visibility {
		case "public":
		case "":
			return 0, fmt.Errorf("%s refused to show %s, and GitHub gives package %s no visibility, so nothing says whether it is absent or private", host, image, pkg)
		default:
			return 0, fmt.Errorf("%w: GitHub gives %s the visibility %q, so no anonymous client can read %s", ErrPrivate, pkg, p.Visibility, image)
		}
		if bytes.Contains(stderr, []byte("manifest unknown")) {
			// A public package without this tag: not published yet.
			return Absent, nil
		}
		return 0, unreadable(image, fmt.Errorf("GitHub lists %s as public, but %s refused an anonymous read: %s", pkg, host, stderr))
	case 403:
		// A token without packages: read gets a 403, and so does one that
		// hit a rate limit or must authorise SSO first: GitHub's message
		// says which.
		return 0, fmt.Errorf("%s refused to show %s, and GitHub would not show package %s to this token: HTTP 403: %s", host, image, pkg, said(resp.Message))
	default:
		return 0, fmt.Errorf("%s refused to show %s, and GitHub answered HTTP %d for package %s: %s", host, image, resp.Status, pkg, said(resp.Message))
	}
}

// said returns GitHub's message, or says it gave none.
func said(message string) string {
	if message == "" {
		return "GitHub gave no message"
	}
	return message
}

// unreadable is the error for an image nothing could read, whatever was
// asked of it: which commit it was built from, or only whether it is
// published.
func unreadable(image string, err error) error {
	return fmt.Errorf("could not read %s: %w", image, err)
}

// parse returns the owner and package name of a ghcr.io reference, which
// may carry a tag, a digest or both. A name may hold slashes, as in
// ghcr.io/divbast/a/b.
func parse(image string) (owner, name string, err error) {
	path, ok := strings.CutPrefix(image, host+"/")
	if !ok {
		return "", "", fmt.Errorf("%q is not a %s image: only %s packages can be told absent from private", image, host, host)
	}
	path, _, _ = strings.Cut(path, "@")
	if i := strings.LastIndex(path, ":"); i > strings.LastIndex(path, "/") {
		path = path[:i]
	}
	owner, name, ok = strings.Cut(path, "/")
	if !ok || owner == "" || name == "" {
		return "", "", fmt.Errorf("%q names no %s owner and package, as in %s/divbast/librespeed:latest", image, host, host)
	}
	return owner, name, nil
}
