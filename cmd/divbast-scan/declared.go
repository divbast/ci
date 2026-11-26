// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/divbast/ci/internal/execx"
	"github.com/divbast/ci/internal/ocilayout"
	"github.com/divbast/ci/internal/registry"
	"github.com/divbast/ci/internal/scan"
)

// An image declares files to the scan in a label of its own for each
// kind, as absolute paths in the image separated by commas: the
// lockfiles of the packages that built it, and SBOMs of what it ships
// that no image scan sees.

// declaredPaths reads label in labels, the labels of the image image
// names: the paths it names in the image, without their leading slash, in
// its order, or none when it is not there. Each must be absolute and
// clean, come once, and be a file the scan reads, which unreadable
// refuses by saying why, or allows by returning "". A label that names
// none, or one any other way, is an error.
func declaredPaths(labels map[string]string, label, image string, unreadable func(p string) string) ([]string, error) {
	value, ok := labels[label]
	if !ok {
		return nil, nil
	}
	var paths []string
	for p := range strings.SplitSeq(value, ",") {
		p = strings.TrimSpace(p)
		switch {
		case p == "":
			return nil, fmt.Errorf("%s's %s label is %q, with an empty path in it: name each file once, separated by commas", image, label, value)
		case !path.IsAbs(p) || path.Clean(p) != p || p == "/":
			return nil, fmt.Errorf("%s's %s label names %q, which is no clean absolute path in the image", image, label, p)
		}
		if why := unreadable(p); why != "" {
			return nil, fmt.Errorf("%s's %s label names %s, but %s", image, label, p, why)
		}
		p = strings.TrimPrefix(p, "/")
		if slices.Contains(paths, p) {
			return nil, fmt.Errorf("%s's %s label names /%s twice", image, label, p)
		}
		paths = append(paths, p)
	}
	return paths, nil
}

// declaredBy reads which files the linux/arch image in the OCI layout at
// layout declares, in its labels: its lockfiles and its SBOMs, none of
// either when it has no such label. name is what the errors call the
// image. A config that cannot be read is an error that says no more than
// that.
func declaredBy(layout, arch, name string) (locks, boms []string, err error) {
	im, err := ocilayout.OpenAs(layout, arch, name)
	if err != nil {
		return nil, nil, fmt.Errorf("could not read %s's config, so nothing says which files it declares to the scan: %w", name, err)
	}
	defer func() { _ = im.Close() }() // read-only, so nothing to lose
	cfg, err := im.Config()
	if err != nil {
		return nil, nil, fmt.Errorf("could not read %s's config, so nothing says which files it declares to the scan: %w", name, err)
	}
	if locks, err = declared(cfg.Labels, name); err != nil {
		return nil, nil, err
	}
	if boms, err = declaredSBOMs(cfg.Labels, name); err != nil {
		return nil, nil, err
	}
	return locks, boms, nil
}

// readDeclared reads paths, files the linux/arch image in the OCI layout
// at layout declares in its label label, from its layers, each of at most
// limit bytes. Each must be a file there, not a symlink. name is what the
// errors call the image.
func readDeclared(ctx context.Context, zstd execx.StreamRunner, layout, arch, name, label string, paths []string, limit int64) (map[string][]byte, error) {
	im, err := ocilayout.OpenAs(layout, arch, name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = im.Close() }() // read-only, so nothing to lose
	tree, err := im.Files(ctx, zstd, func(p string) (int64, bool) { return limit, slices.Contains(paths, p) })
	if err != nil {
		return nil, err
	}
	files := make(map[string][]byte, len(paths))
	for _, p := range paths {
		n, ok := tree[p]
		switch {
		case !ok:
			return nil, fmt.Errorf("%s declares /%s in its %s label, but holds no file there", name, p, label)
		case n.Link != "":
			return nil, fmt.Errorf("%s declares /%s in its %s label, but it is a symlink, to %s: declare the file itself", name, p, label, n.Link)
		}
		files[p] = n.Body
	}
	return files, nil
}

// writeUnder makes the directory root, and writes files under it, each
// at its path in paths, the path in the image, through an [os.Root] on
// it.
func writeUnder(root string, paths []string, files map[string][]byte) (err error) {
	err = os.Mkdir(root, 0o700)
	if err != nil {
		return err
	}
	dir, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, dir.Close()) }()
	for _, p := range paths {
		err = dir.MkdirAll(path.Dir(p), 0o700)
		if err == nil {
			err = dir.WriteFile(p, files[p], 0o600)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// publishedDeclared copies ref, the published image as pinned, for
// linux/arch, into tmp, with skopeo, and reads which files its own labels
// declare, naming it ref in every error, never the copy's directory. Of
// each kind the candidate declares, locks and boms, it scans what ref
// declares with g, writing the reports beside baseline, and adds their
// findings to shipped and their packages to inventory. It reports, for
// each kind, whether ref carries none, and says so on stdout. Its errors
// say what could not be told.
func publishedDeclared(ctx context.Context, lookup registry.Lookup, zstd execx.StreamRunner, g scan.Grype,
	locks lockfiles, boms sboms, ref, arch, tmp, baseline string, shipped *[]scan.Finding, inventory *[]scan.Pkg, stdout io.Writer,
) (uncarriedLocks, uncarriedBOMs bool, err error) {
	var kinds []string
	if len(locks.paths) > 0 {
		kinds = append(kinds, "lockfiles")
	}
	if len(boms.paths) > 0 {
		kinds = append(kinds, "SBOMs")
	}
	layout := filepath.Join(tmp, "published-layout")
	err = lookup.Copy(ctx, ref, arch, layout)
	var pubLocks, pubBOMs []string
	if err == nil {
		pubLocks, pubBOMs, err = declaredBy(layout, arch, ref)
	}
	if err != nil {
		return false, false, fmt.Errorf("could not tell which %s %s carries, so no finding in them can be told apart from one already published: %w",
			strings.Join(kinds, " and "), ref, err)
	}
	if len(locks.paths) > 0 {
		if uncarriedLocks, err = publishedLockfiles(ctx, zstd, g, layout, ref, arch, tmp, baseline, pubLocks, shipped, inventory); err != nil {
			return false, false, fmt.Errorf("could not tell which lockfiles %s carries, so no finding in a lockfile can be told apart from one already published: %w", ref, err)
		}
		if uncarriedLocks {
			if _, err = fmt.Fprintf(stdout, "%s carries no lockfile, so the findings in %s are listed, not blocking, until a published image carries one\n", ref, locks); err != nil {
				return false, false, fmt.Errorf("write the lockfiles: %w", err)
			}
		}
	}
	if len(boms.paths) > 0 {
		if uncarriedBOMs, err = publishedSBOMs(ctx, zstd, g, layout, ref, arch, tmp, baseline, pubBOMs, shipped, inventory); err != nil {
			return false, false, fmt.Errorf("could not tell which SBOMs %s carries, so no finding in an SBOM can be told apart from one already published: %w", ref, err)
		}
		if uncarriedBOMs {
			if _, err = fmt.Fprintf(stdout, "%s carries no SBOM, so the findings in %s are listed, not blocking, until a published image carries one\n", ref, boms); err != nil {
				return false, false, fmt.Errorf("write the SBOMs: %w", err)
			}
		}
	}
	return uncarriedLocks, uncarriedBOMs, nil
}
