// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package coreprobe

import (
	"context"
	"fmt"
	"os"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/divbast/ci/harness/probekit"
)

// wOK is access(2)'s W_OK: may the caller write it.
const wOK = 0x2

// The filesystems of a mount that no file the container writes lands on:
// the kernel's own views, and its terminals and message queues.
var kernelFilesystems = []string{"proc", "sysfs", "cgroup", "cgroup2", "devpts", "mqueue"}

// mountFlags are the flags every writable mount must carry, in the order
// a record names them.
var mountFlags = []string{"noexec", "nosuid", "nodev"}

// packageManagers are the names a package manager's binary goes by, and
// systemDirs where one is put, beside PID 1's PATH.
var (
	packageManagers = []string{"dpkg", "dpkg-deb", "apt", "apt-get", "apk", "rpm", "dnf", "microdnf", "yum"}
	systemDirs      = []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"}
)

// statusValue returns the value of PID 1's status line field, or
// "absent" when there is none.
func (env *Env) statusValue(field string) (string, error) {
	status, err := env.readProc("1/status")
	if err != nil {
		return "", err
	}
	if v, err := statusField(status, field, `(\d+)`); err == nil {
		return v[0], nil
	}
	return absent, nil
}

// assertNoNewPrivs checks that PID 1 runs with no_new_privs, so that
// nothing it execs can gain a privilege its parent lacks.
func (env *Env) assertNoNewPrivs(_ context.Context, out *probekit.Output, _ []string) error {
	v, err := env.statusValue("NoNewPrivs")
	if err != nil {
		return err
	}
	out.Equal("PID 1 has no_new_privs set (NoNewPrivs in /proc/1/status)", "1", v)
	return nil
}

// assertSeccomp checks that PID 1 is confined by a seccomp filter, mode
// 2: the engine's default profile, or any other.
func (env *Env) assertSeccomp(_ context.Context, out *probekit.Output, _ []string) error {
	v, err := env.statusValue("Seccomp")
	if err != nil {
		return err
	}
	out.Equal("PID 1 is confined by a seccomp filter (Seccomp in /proc/1/status)", "2", v)
	return nil
}

// mount is one line of a mountinfo file, as far as the checks read it.
type mount struct {
	point, fstype string
	options       []string
}

// mountEscape is one octal escape in a mountinfo path: \040 for a space,
// \011 a tab, \012 a newline and \134 a backslash.
var mountEscape = regexp.MustCompile(`\\[0-7]{3}`)

// parseMountinfo reads a mountinfo file: per line, the mount ID, the
// parent's, major:minor, the root, the mount point and the per-mount
// options, then optional fields up to a lone "-", then the filesystem
// type, the source and the superblock's options.
func parseMountinfo(text string) ([]mount, error) {
	var mounts []mount
	for line := range strings.Lines(text) {
		line = strings.TrimSuffix(line, "\n")
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		sep := slices.Index(f, "-")
		if len(f) < 6 || sep < 6 || sep+1 >= len(f) {
			return nil, fmt.Errorf("/proc/1/mountinfo has a line that is not a mount: %s", line)
		}
		point := mountEscape.ReplaceAllStringFunc(f[4], func(e string) string {
			n, _ := strconv.ParseUint(e[1:], 8, 8)
			return string(rune(n))
		})
		mounts = append(mounts, mount{point: point, fstype: f[sep+1], options: strings.Split(f[5], ",")})
	}
	return mounts, nil
}

// topmost returns the last mount at each point, in the order the points
// first appear: a mount stacked on another hides it.
func topmost(mounts []mount) []mount {
	var order []string
	last := make(map[string]mount)
	for _, m := range mounts {
		if _, seen := last[m.point]; !seen {
			order = append(order, m.point)
		}
		last[m.point] = m
	}
	top := make([]mount, len(order))
	for i, p := range order {
		top[i] = last[p]
	}
	return top
}

// writable reports whether the container's user can create a file on m:
// a read-write mount of a directory, on a filesystem files are written
// to, that the user may write.
func (env *Env) writable(m mount) bool {
	if !slices.Contains(m.options, "rw") || slices.Contains(kernelFilesystems, m.fstype) {
		return false
	}
	p := env.path(m.point)
	if info, err := os.Lstat(p); err != nil || !info.IsDir() {
		return false
	}
	return env.Access(p, wOK) == nil
}

// assertWritableMounts checks that every mount the container's user can
// write carries noexec, nosuid and nodev, but for the targets given,
// which the app declares as its own, and that /tmp is a tmpfs the user
// can write. So nothing the container writes can be run, and /tmp is the
// one place it writes, beside what it declares.
func (env *Env) assertWritableMounts(_ context.Context, out *probekit.Output, declared []string) error {
	for _, d := range declared {
		if !path.IsAbs(d) {
			return fmt.Errorf("'%s' is not an absolute path", d)
		}
	}
	text, err := env.readProc("1/mountinfo")
	if err != nil {
		return err
	}
	mounts, err := parseMountinfo(text)
	if err != nil {
		return err
	}

	tmp := absent
	for _, m := range topmost(mounts) {
		w := env.writable(m)
		if m.point == "/tmp" {
			tmp = m.fstype
			if !w {
				tmp += ", not writable"
			}
		}
		if !w || slices.Contains(declared, m.point) {
			continue
		}
		var have []string
		for _, flag := range mountFlags {
			if slices.Contains(m.options, flag) {
				have = append(have, flag)
			}
		}
		found := strings.Join(have, " ")
		if found == "" {
			found = "none"
		}
		out.Equal(m.point+" is mounted noexec, nosuid and nodev", strings.Join(mountFlags, " "), found)
	}
	out.Equal("/tmp is a tmpfs the container can write", "tmpfs", tmp)
	return nil
}

// pathDirs returns the directories of PID 1's PATH, from its environment:
// none when it sets no PATH, and only absolute ones.
func (env *Env) pathDirs() ([]string, error) {
	environ, err := env.readProc("1/environ")
	if err != nil {
		return nil, err
	}
	var dirs []string
	for kv := range strings.SplitSeq(environ, "\x00") {
		if v, ok := strings.CutPrefix(kv, "PATH="); ok {
			for d := range strings.SplitSeq(v, ":") {
				if path.IsAbs(d) {
					dirs = append(dirs, path.Clean(d))
				}
			}
		}
	}
	return dirs, nil
}

// assertNoPackageManager checks that no package manager is in the image,
// in PID 1's PATH or any of the directories one is put in. A path the
// probe may not look up counts as one, since it may be there. It reads no
// package database: /var/lib/dpkg/status.d stays, since that is how a
// scanner lists the image's Debian packages.
func (env *Env) assertNoPackageManager(_ context.Context, out *probekit.Output, _ []string) error {
	dirs, err := env.pathDirs()
	if err != nil {
		return err
	}
	var found []string
	for _, d := range slices.Compact(slices.Sorted(slices.Values(slices.Concat(dirs, systemDirs)))) {
		for _, name := range packageManagers {
			if p := path.Join(d, name); env.presence(p) != absent {
				found = append(found, p)
			}
		}
	}
	slices.Sort(found)
	got := strings.Join(found, " ")
	if got == "" {
		got = "none"
	}
	out.Record(len(found) == 0, "no package manager is in the image", "none", got)
	return nil
}
