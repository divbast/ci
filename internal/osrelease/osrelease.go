// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Package osrelease reads the os-release file of an image in an OCI
// layout: what the image says it is, before any scanner says what it
// thinks it is.
//
// A scanner reads an image's OS through its own model, and a model can be
// wrong without being blind: Trivy reads a Docker Hardened Image that says
// ID=dhi, but keeps /etc/debian_version, as plain Debian, and scans it
// against Debian's advisories. Only the image's own word shows the
// mismatch, so the scan reads it here, from the layers themselves, and
// holds the scanner's report against it.
package osrelease

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/divbast/ci/internal/execx"
	"github.com/divbast/ci/internal/ocilayout"
)

// Info is what an os-release file says of the OS: its ID, ID_LIKE and
// VERSION_ID, each as the file sets it, unquoted, or "" when it does not.
type Info struct{ ID, IDLike, VersionID string }

// maxSize bounds an os-release file, a few hundred bytes in practice.
const maxSize = 64 << 10

// Read reads the os-release file of the linux/arch image in the OCI
// layout at layout, as a container of it would find it: /etc/os-release,
// or /usr/lib/os-release when that is missing, as os-release(5) says,
// across the image's layers in order, with whiteouts honoured. One
// symlink is followed, inside the image's root: /etc/os-release is
// usually one, to ../usr/lib/os-release. zstd runs the zstd command for
// zstd layers.
//
// The image is the one [ocilayout.Open] opens for linux/arch. It returns
// false, and no error, for an image with no os-release; an error for a
// layout it cannot read, one with no such image, or an os-release it
// cannot follow.
func Read(ctx context.Context, zstd execx.StreamRunner, layout, arch string) (Info, bool, error) {
	im, err := ocilayout.Open(layout, arch)
	if err != nil {
		return Info{}, false, err
	}
	defer func() { _ = im.Close() }() // read-only, so nothing to lose
	fs, err := im.Files(ctx, zstd, func(name string) (int64, bool) { return maxSize, path.Base(name) == "os-release" })
	if err != nil {
		return Info{}, false, err
	}
	info, ok, err := osRelease(fs)
	if err != nil {
		return Info{}, false, fmt.Errorf("%s: %w", layout, err)
	}
	return info, ok, nil
}

// Arch returns the architecture of the one linux image in the OCI layout
// at layout, as its index names it, or as its config says when the index
// names no platform, as Podman's archives do. The scan builds one image
// for one architecture, and needs to know which before any scanner runs;
// a layout of several images, or of none, is an error.
func Arch(layout string) (arch string, err error) {
	im, err := ocilayout.Open(layout, "")
	if err != nil {
		return "", err
	}
	defer func() { _ = im.Close() }() // read-only, so nothing to lose
	if p := im.Platform(); p != "" {
		return p, nil
	}
	cfg, err := im.Config()
	if err != nil {
		return "", err
	}
	if cfg.Architecture == "" {
		return "", fmt.Errorf("%s: the image's config names no architecture", layout)
	}
	return cfg.Architecture, nil
}

// osRelease is the os-release file fs, the files of an image named
// os-release, leaves, read.
func osRelease(fs map[string]ocilayout.Node) (Info, bool, error) {
	for _, p := range []string{"etc/os-release", "usr/lib/os-release"} {
		n, ok := fs[p]
		if !ok {
			continue
		}
		if n.Link != "" {
			// Resolved as the kernel would inside the image's root, where
			// ".." at the root stays there
			target := n.Link
			if !path.IsAbs(target) {
				target = path.Join("/", path.Dir(p), target)
			}
			target = strings.TrimPrefix(path.Clean(target), "/")
			if path.Base(target) != "os-release" {
				return Info{}, false, fmt.Errorf("/%s is a symlink to /%s, which the reader does not keep", p, target)
			}
			t, ok := fs[target]
			if !ok {
				// A link to nothing is no file, so the next one counts
				continue
			}
			if t.Link != "" {
				return Info{}, false, fmt.Errorf("/%s is a symlink to /%s, itself a symlink: the reader follows one", p, target)
			}
			n = t
		}
		return parse(n.Body), true, nil
	}
	return Info{}, false, nil
}

// parse reads the variables Info holds from an os-release file, as
// os-release(5) writes them: KEY=value lines, values quoted as in a
// shell, and comments and blank lines skipped.
func parse(data []byte) Info {
	var info Info
	for line := range strings.Lines(string(data)) {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "ID":
			info.ID = unquote(value)
		case "ID_LIKE":
			info.IDLike = unquote(value)
		case "VERSION_ID":
			info.VersionID = unquote(value)
		}
	}
	return info
}

// unquote undoes a value's shell quoting: single quotes keep everything,
// and elsewhere a backslash escapes the character after it.
func unquote(v string) string {
	if len(v) >= 2 && v[0] == '\'' && v[len(v)-1] == '\'' {
		return v[1 : len(v)-1]
	}
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		v = v[1 : len(v)-1]
	}
	var b strings.Builder
	escaped := false
	for _, r := range v {
		if r == '\\' && !escaped {
			escaped = true
			continue
		}
		escaped = false
		b.WriteRune(r)
	}
	return b.String()
}
