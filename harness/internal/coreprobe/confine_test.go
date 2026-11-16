// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package coreprobe

import (
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"testing/fstest"
)

func TestNoNewPrivs(t *testing.T) {
	t.Parallel()

	const what = "PID 1 has no_new_privs set (NoNewPrivs in /proc/1/status)"
	tests := []struct {
		name     string
		status   string
		wantCode int
		want     string
	}{
		{name: "set", status: status, want: record(true, what, "1", "1")},
		{name: "unset", status: strings.Replace(status, "NoNewPrivs:\t1", "NoNewPrivs:\t0", 1), wantCode: 1, want: record(false, what, "1", "0")},
		{name: "missing", status: strings.Replace(status, "NoNewPrivs:\t1\n", "", 1), wantCode: 1, want: record(false, what, "1", "absent")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			code, stdout, _ := probe(t, testEnv(t, fstest.MapFS{"1/status": file(tt.status)}, ""), "assert-no-new-privs")
			if code != tt.wantCode || stdout != tt.want {
				t.Errorf("assert-no-new-privs = exit %d, stdout %q; want exit %d, stdout %q", code, stdout, tt.wantCode, tt.want)
			}
		})
	}
}

func TestSeccomp(t *testing.T) {
	t.Parallel()

	const what = "PID 1 is confined by a seccomp filter (Seccomp in /proc/1/status)"
	tests := []struct {
		name     string
		status   string
		wantCode int
		want     string
	}{
		{name: "filter", status: status, want: record(true, what, "2", "2")},
		{name: "unconfined", status: strings.Replace(status, "Seccomp:\t2", "Seccomp:\t0", 1), wantCode: 1, want: record(false, what, "2", "0")},
		{name: "strict", status: strings.Replace(status, "Seccomp:\t2", "Seccomp:\t1", 1), wantCode: 1, want: record(false, what, "2", "1")},
		{name: "missing", status: strings.Replace(status, "Seccomp:\t2\n", "", 1), wantCode: 1, want: record(false, what, "2", "absent")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			code, stdout, _ := probe(t, testEnv(t, fstest.MapFS{"1/status": file(tt.status)}, ""), "assert-seccomp")
			if code != tt.wantCode || stdout != tt.want {
				t.Errorf("assert-seccomp = exit %d, stdout %q; want exit %d, stdout %q", code, stdout, tt.wantCode, tt.want)
			}
		})
	}
}

// mountRoot makes a root with a directory at each mount point a writable
// mount could be, and returns it with an Access that lets the container's
// user write only the mount points in writable.
func mountRoot(t *testing.T, writable ...string) (root string, access func(string, uint32) error) {
	t.Helper()
	root = tree(t, nil, "tmp", "dev/shm", "run", "var/tmp", "data")
	return root, func(p string, mode uint32) error {
		if mode != wOK {
			return errors.New("asked for something other than W_OK")
		}
		for _, w := range writable {
			if p == filepath.Join(root, w) {
				return nil
			}
		}
		return syscall.EACCES
	}
}

func TestWritableMountsFixtures(t *testing.T) {
	t.Parallel()

	tmpOK := record(true, "/tmp is mounted noexec, nosuid and nodev", "noexec nosuid nodev", "noexec nosuid nodev") +
		record(true, "/tmp is a tmpfs the container can write", "tmpfs", "tmpfs")
	tests := []struct {
		name      string
		mountinfo string
		writable  []string
		declared  []string
		wantCode  int
		want      string
	}{
		// Docker's /dev is tmpfs and rw, with no noexec, but root's and
		// 0755; /etc/hosts and the rest are files; /proc and /sys are
		// neither.
		{name: "docker", mountinfo: fixture(t, "mountinfo-docker"), writable: []string{"/tmp"}, want: tmpOK},
		{
			name:      "docker-shm-writable",
			mountinfo: fixture(t, "mountinfo-docker"),
			writable:  []string{"/tmp", "/dev/shm"},
			want:      record(true, "/dev/shm is mounted noexec, nosuid and nodev", "noexec nosuid nodev", "noexec nosuid nodev") + tmpOK,
		},
		{name: "podman", mountinfo: fixture(t, "mountinfo-podman"), writable: []string{"/tmp"}, want: tmpOK},
		{
			// Podman without --read-only-tmpfs=false adds /run and
			// /var/tmp, neither noexec
			name:      "podman-readonly-tmpfs",
			mountinfo: fixture(t, "mountinfo-podman-readonly-tmpfs"),
			writable:  []string{"/tmp", "/run", "/var/tmp"},
			wantCode:  1,
			want: record(true, "/tmp is mounted noexec, nosuid and nodev", "noexec nosuid nodev", "noexec nosuid nodev") +
				record(false, "/run is mounted noexec, nosuid and nodev", "noexec nosuid nodev", "nosuid nodev") +
				record(false, "/var/tmp is mounted noexec, nosuid and nodev", "noexec nosuid nodev", "nosuid nodev") +
				record(true, "/tmp is a tmpfs the container can write", "tmpfs", "tmpfs"),
		},
		{
			name:      "an-executable-tmp",
			mountinfo: strings.Replace(fixture(t, "mountinfo-docker"), "/tmp rw,nosuid,nodev,noexec,relatime", "/tmp rw,nosuid,nodev,relatime", 1),
			writable:  []string{"/tmp"},
			wantCode:  1,
			want: record(false, "/tmp is mounted noexec, nosuid and nodev", "noexec nosuid nodev", "nosuid nodev") +
				record(true, "/tmp is a tmpfs the container can write", "tmpfs", "tmpfs"),
		},
		{
			name:      "no-tmp",
			mountinfo: dropLine(fixture(t, "mountinfo-docker"), " /tmp "),
			writable:  []string{"/tmp"},
			wantCode:  1,
			want:      record(false, "/tmp is a tmpfs the container can write", "tmpfs", "absent"),
		},
		{
			name:      "a-tmp-the-container-cannot-write",
			mountinfo: fixture(t, "mountinfo-docker"),
			wantCode:  1,
			want:      record(false, "/tmp is a tmpfs the container can write", "tmpfs", "tmpfs, not writable"),
		},
		{
			// Baikal's /data, a volume: writable and exec, and declared
			name:      "a-declared-volume",
			mountinfo: fixture(t, "mountinfo-docker-data"),
			writable:  []string{"/tmp", "/data"},
			declared:  []string{"/data"},
			want:      tmpOK,
		},
		{
			name:      "an-undeclared-volume",
			mountinfo: fixture(t, "mountinfo-docker-data"),
			writable:  []string{"/tmp", "/data"},
			wantCode:  1,
			want:      record(false, "/data is mounted noexec, nosuid and nodev", "noexec nosuid nodev", "none") + tmpOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			root, access := mountRoot(t, tt.writable...)
			env := testEnv(t, fstest.MapFS{"1/mountinfo": file(tt.mountinfo)}, root)
			env.Access = access
			code, stdout, stderr := probe(t, env, slices.Concat([]string{"assert-writable-mounts"}, tt.declared)...)
			if code != tt.wantCode || stdout != tt.want {
				t.Errorf("assert-writable-mounts %q = exit %d, stdout %q, stderr %q; want exit %d, stdout %q",
					tt.declared, code, stdout, stderr, tt.wantCode, tt.want)
			}
		})
	}
}

func TestWritableMountsEscapes(t *testing.T) {
	t.Parallel()

	root := tree(t, nil, "tmp", "my dir")
	mountinfo := "1 0 0:1 / / ro - overlay overlay rw\n" +
		"2 1 0:2 / /tmp rw,nosuid,nodev,noexec - tmpfs tmpfs rw\n" +
		"3 1 0:3 / /my\\040dir rw,shared:5 - tmpfs tmpfs rw\n"
	env := testEnv(t, fstest.MapFS{"1/mountinfo": file(mountinfo)}, root)
	env.Access = func(string, uint32) error { return nil }
	code, stdout, _ := probe(t, env, "assert-writable-mounts")
	want := record(true, "/tmp is mounted noexec, nosuid and nodev", "noexec nosuid nodev", "noexec nosuid nodev") +
		record(false, "/my dir is mounted noexec, nosuid and nodev", "noexec nosuid nodev", "none") +
		record(true, "/tmp is a tmpfs the container can write", "tmpfs", "tmpfs")
	if code != 1 || stdout != want {
		t.Errorf("assert-writable-mounts = exit %d, stdout %q; want exit 1, stdout %q", code, stdout, want)
	}
}

func TestWritableMountsRefusals(t *testing.T) {
	t.Parallel()

	env := testEnv(t, fstest.MapFS{"1/mountinfo": file("this is not a mount\n")}, "")
	if code, stdout, _ := probe(t, env, "assert-writable-mounts"); code != 1 || !strings.Contains(stdout, "assert-writable-mounts completed") {
		t.Errorf("a malformed mountinfo = exit %d, stdout %q; want the subcommand recorded as failing", code, stdout)
	}
	if code, stdout, _ := probe(t, env, "assert-writable-mounts", "data"); code != 1 || !strings.Contains(stdout, "'data' is not an absolute path") {
		t.Errorf("a relative declared target = exit %d, stdout %q; want it refused", code, stdout)
	}
}

// dropLine returns text without the lines that hold needle.
func dropLine(text, needle string) string {
	var kept []string
	for line := range strings.Lines(text) {
		if !strings.Contains(line, needle) {
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "")
}

func TestNoPackageManager(t *testing.T) {
	t.Parallel()

	const what = "no package manager is in the image"
	tests := []struct {
		name     string
		files    map[string]string
		environ  string
		wantCode int
		want     string
	}{
		{name: "none", want: record(true, what, "none", "none")},
		{name: "dpkg", files: map[string]string{"usr/bin/dpkg": "x"}, wantCode: 1, want: record(false, what, "none", "/usr/bin/dpkg")},
		{
			name:     "on-pid-1s-path",
			files:    map[string]string{"opt/bin/apk": "x"},
			environ:  "HOME=/\x00PATH=/opt/bin:/usr/bin\x00",
			wantCode: 1,
			want:     record(false, what, "none", "/opt/bin/apk"),
		},
		{
			name:     "several-sorted",
			files:    map[string]string{"usr/sbin/yum": "x", "bin/apt-get": "x", "usr/local/bin/microdnf": "x"},
			wantCode: 1,
			want:     record(false, what, "none", "/bin/apt-get /usr/local/bin/microdnf /usr/sbin/yum"),
		},
		{
			// What Trivy reads to list the image's packages stays
			name: "dpkg-status-is-no-package-manager",
			files: map[string]string{
				"var/lib/dpkg/status.d/libc6":        "Package: libc6\n",
				"var/lib/dpkg/status.d/libc6.md5sum": "x",
			},
			want: record(true, what, "none", "none"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			proc := fstest.MapFS{"1/environ": file(tt.environ)}
			code, stdout, stderr := probe(t, testEnv(t, proc, tree(t, tt.files)), "assert-no-package-manager")
			if code != tt.wantCode || stdout != tt.want {
				t.Errorf("assert-no-package-manager = exit %d, stdout %q, stderr %q; want exit %d, stdout %q", code, stdout, stderr, tt.wantCode, tt.want)
			}
		})
	}
}

func TestNoPackageManagerUnsearchable(t *testing.T) {
	t.Parallel()

	root := tree(t, nil)
	unsearchable(t, root, "usr/sbin")
	code, stdout, _ := probe(t, testEnv(t, fstest.MapFS{"1/environ": file("")}, root), "assert-no-package-manager")
	if code != 1 || !strings.Contains(stdout, "/usr/sbin/dpkg") {
		t.Errorf("assert-no-package-manager with /usr/sbin unsearchable = exit %d, stdout %q; want each name there found, since it may be there", code, stdout)
	}
}
