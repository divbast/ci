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
	"github.com/divbast/ci/internal/pnpmlock"
	"github.com/divbast/ci/internal/registry"
	"github.com/divbast/ci/internal/scan"
)

// lockfileLabel is the image label that declares the lockfiles an image
// ships, of the packages that built it: absolute paths in the image,
// separated by commas.
const lockfileLabel = "io.github.divbast.scan.lockfiles"

// lockfileName is the one kind of lockfile the scan reads: pnpm's.
const lockfileName = "pnpm-lock.yaml"

// maxLockfile bounds a lockfile the scan reads.
const maxLockfile = 64 << 20

// lockfiles is what an image's label declares: each lockfile's path in
// the image, without its leading slash, as the scan lists where a finding
// is, in the label's order, and its content.
type lockfiles struct {
	paths []string
	files map[string][]byte
}

// declared reads the lockfile label of the image whose labels are labels:
// none when it is not there. Each path must be absolute and clean, name a
// pnpm-lock.yaml, and come once; a label that names none, or one any
// other way, is an error. image names the image in the error.
func declared(labels map[string]string, image string) ([]string, error) {
	value, ok := labels[lockfileLabel]
	if !ok {
		return nil, nil
	}
	var paths []string
	for p := range strings.SplitSeq(value, ",") {
		p = strings.TrimSpace(p)
		switch {
		case p == "":
			return nil, fmt.Errorf("%s's %s label is %q, with an empty path in it: name each lockfile once, separated by commas", image, lockfileLabel, value)
		case !path.IsAbs(p) || path.Clean(p) != p || p == "/":
			return nil, fmt.Errorf("%s's %s label names %q, which is no clean absolute path in the image", image, lockfileLabel, p)
		case path.Base(p) != lockfileName:
			return nil, fmt.Errorf("%s's %s label names %s, but the scan reads only pnpm's lockfiles, named %s", image, lockfileLabel, p, lockfileName)
		}
		p = strings.TrimPrefix(p, "/")
		if slices.Contains(paths, p) {
			return nil, fmt.Errorf("%s's %s label names /%s twice", image, lockfileLabel, p)
		}
		paths = append(paths, p)
	}
	return paths, nil
}

// declaredBy reads which lockfiles the linux/arch image in the OCI layout
// at layout declares, in its label: none when it has none. name is what
// the errors call the image. A config that cannot be read is an error that
// says no more than that.
func declaredBy(layout, arch, name string) ([]string, error) {
	im, err := ocilayout.OpenAs(layout, arch, name)
	if err != nil {
		return nil, fmt.Errorf("could not read %s's config, so nothing says which lockfiles it declares: %w", name, err)
	}
	defer func() { _ = im.Close() }() // read-only, so nothing to lose
	cfg, err := im.Config()
	if err != nil {
		return nil, fmt.Errorf("could not read %s's config, so nothing says which lockfiles it declares: %w", name, err)
	}
	return declared(cfg.Labels, name)
}

// readLockfiles reads paths, the lockfiles the linux/arch image in the
// OCI layout at layout declares, from its layers. Each must be a file
// there. name is what the errors call the image.
func readLockfiles(ctx context.Context, zstd execx.StreamRunner, layout, arch, name string, paths []string) (lockfiles, error) {
	if len(paths) == 0 {
		return lockfiles{}, nil
	}
	im, err := ocilayout.OpenAs(layout, arch, name)
	if err != nil {
		return lockfiles{}, err
	}
	defer func() { _ = im.Close() }() // read-only, so nothing to lose
	tree, err := im.Files(ctx, zstd, func(p string) (int64, bool) { return maxLockfile, slices.Contains(paths, p) })
	if err != nil {
		return lockfiles{}, err
	}
	l := lockfiles{paths: paths, files: map[string][]byte{}}
	for _, p := range paths {
		n, ok := tree[p]
		switch {
		case !ok:
			return lockfiles{}, fmt.Errorf("%s declares /%s in its %s label, but holds no file there", name, p, lockfileLabel)
		case n.Link != "":
			return lockfiles{}, fmt.Errorf("%s declares /%s in its %s label, but it is a symlink, to %s: declare the file itself", name, p, lockfileLabel, n.Link)
		}
		l.files[p] = n.Body
	}
	return l, nil
}

// runtime reads each lockfile of l, to tell its runtime packages from its
// build-only ones.
func (l lockfiles) runtime() (map[string]*pnpmlock.Lockfile, error) {
	read := make(map[string]*pnpmlock.Lockfile, len(l.paths))
	for _, p := range l.paths {
		lock, err := pnpmlock.Read(l.files[p])
		if err != nil {
			return nil, fmt.Errorf("cannot tell the runtime packages of /%s from its build-only ones, so none of its findings can be judged: %w", p, err)
		}
		read[p] = lock
	}
	return read, nil
}

// scan writes l's lockfiles under root, each at its path in the image, and
// has g scan them there, writing its report to report, its CycloneDX to
// cdx, and its SARIF to sarif, unless sarif is "". A lockfile in which
// grype finds no package is refused: a scan of it would prove nothing.
func (l lockfiles) scan(ctx context.Context, g scan.Grype, root, report, cdx, sarif string) (scan.Report, error) {
	if err := l.write(root); err != nil {
		return scan.Report{}, fmt.Errorf("write the lockfiles %s for grype: %w", l, err)
	}
	if err := g.Dir(ctx, root, report, cdx, sarif); err != nil {
		return scan.Report{}, fmt.Errorf("grype could not scan the lockfiles %s: %w", l, err)
	}
	rep, err := parseGrypeFiles(report, cdx)
	if err != nil {
		return scan.Report{}, err
	}
	for _, p := range l.paths {
		if rep.PackagesIn[p] == 0 {
			return scan.Report{}, fmt.Errorf("grype found no package in /%s, so a clean scan of it would prove nothing", p)
		}
	}
	return rep, nil
}

// write makes the directory root, and writes l's lockfiles under it, each
// at its path in the image, through an [os.Root] on it.
func (l lockfiles) write(root string) (err error) {
	err = os.Mkdir(root, 0o700)
	if err != nil {
		return err
	}
	dir, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, dir.Close()) }()
	for _, p := range l.paths {
		err = dir.MkdirAll(path.Dir(p), 0o700)
		if err == nil {
			err = dir.WriteFile(p, l.files[p], 0o600)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// String lists l's paths, as the image names them.
func (l lockfiles) String() string {
	return "/" + strings.Join(l.paths, ", /")
}

// held marks each finding of a lockfile in findings that cannot block:
// one in a package read places outside every runtime graph, BuildOnly,
// and, when uncarried, any other, Uncarried.
func held(findings []scan.Finding, read map[string]*pnpmlock.Lockfile, uncarried bool) {
	for i := range findings {
		f := &findings[i]
		lock, ok := read[f.Where]
		switch {
		case !ok:
		case !lock.Runtime(f.Pkg, f.Version):
			f.Hold = scan.BuildOnly
		case uncarried:
			f.Hold = scan.Uncarried
		}
	}
}

// lockGrype is the grype that scans the lockfiles: the image's scanner,
// for an image that says ID=dhi, whose database its own scan updated, or
// else one of its own, configured in cache, with its database updated
// once for both sides.
func lockGrype(ctx context.Context, sc scanner, cache string, docs []string, r execx.Runner, stderr io.Writer) (scan.Grype, error) {
	if gs, ok := sc.(*grypeScanner); ok {
		return gs.grype, nil
	}
	g := scan.Grype{Run: r, VEX: docs, Log: stderr}
	dir, err := grypeCache(cache)
	if err == nil {
		g.Config, err = g.WriteConfig(dir)
	}
	if err != nil {
		return scan.Grype{}, fmt.Errorf("could not write grype's configuration: %w", err)
	}
	if err = g.UpdateDB(ctx); err != nil {
		return scan.Grype{}, fmt.Errorf("grype could not update its database: %w", err)
	}
	return g, nil
}

// publishedLockfiles copies ref, the published image as pinned, for
// linux/arch, into tmp, with skopeo, and reads the lockfiles its own label
// declares, naming it ref in every error, never the copy's directory. It scans them with g, writing its report beside baseline, and
// adds their findings to shipped and their packages to inventory. It
// reports whether the image carries none.
func publishedLockfiles(ctx context.Context, lookup registry.Lookup, zstd execx.StreamRunner, g scan.Grype,
	ref, arch, tmp, baseline string, shipped *[]scan.Finding, inventory *[]scan.Pkg,
) (uncarried bool, _ error) {
	layout := filepath.Join(tmp, "published-layout")
	if err := lookup.Copy(ctx, ref, arch, layout); err != nil {
		return false, err
	}
	paths, err := declaredBy(layout, arch, ref)
	if err != nil {
		return false, err
	}
	if len(paths) == 0 {
		return true, nil
	}
	locks, err := readLockfiles(ctx, zstd, layout, arch, ref, paths)
	if err != nil {
		return false, err
	}
	rep, err := locks.scan(ctx, g, filepath.Join(tmp, "published"), baseline+".lockfiles.json", baseline+".lockfiles.cdx.json", "")
	if err != nil {
		return false, err
	}
	*shipped = append(*shipped, rep.Findings...)
	*inventory = append(*inventory, rep.Inventory...)
	return false, nil
}
