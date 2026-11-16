// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package coreprobe

import (
	"strings"
	"testing"
	"testing/fstest"
)

// frankenphpArgv is LibreSpeed's PID 1, as the kernel keeps it.
const frankenphpArgv = "/usr/local/bin/frankenphp\x00run\x00--config\x00/etc/frankenphp/Caddyfile\x00"

func TestAssertPID1(t *testing.T) {
	t.Parallel()

	argv := []string{"/usr/local/bin/frankenphp", "run", "--config", "/etc/frankenphp/Caddyfile"}
	argvJSON := `["/usr/local/bin/frankenphp","run","--config","/etc/frankenphp/Caddyfile"]`
	tests := []struct {
		name     string
		proc     fstest.MapFS
		args     []string
		wantCode int
		want     string
	}{
		{
			name: "the-server-as-pid-1",
			proc: fstest.MapFS{"1/comm": file("frankenphp\n"), "1/cmdline": file(frankenphpArgv)},
			args: argv,
			want: record(true, "PID 1 comm", "frankenphp", "frankenphp") + record(true, "PID 1 argv", argvJSON, argvJSON),
		},
		{
			name:     "an-init-as-pid-1",
			proc:     fstest.MapFS{"1/comm": file("docker-init\n"), "1/cmdline": file("/sbin/docker-init\x00--\x00/usr/local/bin/frankenphp\x00")},
			args:     argv,
			wantCode: 1,
			want: record(false, "PID 1 comm", "frankenphp", "docker-init") +
				record(false, "PID 1 argv", argvJSON, `["/sbin/docker-init","--","/usr/local/bin/frankenphp"]`),
		},
		{
			// The right binary, run with other arguments: only the whole
			// argv tells the two apart.
			name:     "the-server-binary-with-another-argv",
			proc:     fstest.MapFS{"1/comm": file("frankenphp\n"), "1/cmdline": file(frankenphpArgv)},
			args:     []string{"/usr/local/bin/frankenphp", "run", "--config", "/etc/frankenphp/Other"},
			wantCode: 1,
			want: record(true, "PID 1 comm", "frankenphp", "frankenphp") +
				record(false, "PID 1 argv", `["/usr/local/bin/frankenphp","run","--config","/etc/frankenphp/Other"]`, argvJSON),
		},
		{
			// comm is the executable's name cut to 15 bytes
			name: "a-long-name",
			proc: fstest.MapFS{"1/comm": file("librespeed-boot\n"), "1/cmdline": file("/usr/local/bin/librespeed-bootstrap\x00")},
			args: []string{"/usr/local/bin/librespeed-bootstrap"},
			want: record(true, "PID 1 comm", "librespeed-boot", "librespeed-boot") +
				record(true, "PID 1 argv", `["/usr/local/bin/librespeed-bootstrap"]`, `["/usr/local/bin/librespeed-bootstrap"]`),
		},
		{
			// As PHP's json_encode: slashes kept, non-ASCII escaped, and
			// bytes that are not UTF-8 replaced.
			name:     "json-as-php-writes-it",
			proc:     fstest.MapFS{"1/comm": file("x\n"), "1/cmdline": file("/x\x00caf\xc3\xa9 <&>\x00\xff\"\\\x00")},
			args:     []string{"/x"},
			wantCode: 1,
			want:     record(true, "PID 1 comm", "x", "x") + record(false, "PID 1 argv", `["/x"]`, "[\"/x\",\"caf\\u00e9 <&>\",\"\\ufffd\\\"\\\\\"]"),
		},
		{
			name:     "no-comm",
			proc:     fstest.MapFS{"1/cmdline": file(frankenphpArgv)},
			args:     argv,
			wantCode: 1,
			want:     record(false, "assert-pid1 completed", "no exception", "cannot read /proc/1/comm"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			code, stdout, stderr := probe(t, testEnv(t, tt.proc, ""), append([]string{"assert-pid1"}, tt.args...)...)
			if code != tt.wantCode || stdout != tt.want {
				t.Errorf("assert-pid1 = exit %d, stdout %q, stderr %q; want exit %d, stdout %q", code, stdout, stderr, tt.wantCode, tt.want)
			}
		})
	}
}

func TestUser(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		status   string
		wantCode int
		want     string
	}{
		{name: "both-lines", status: status, want: "Uid:\t65532\t65532\t65532\t65532\nGid:\t65532\t65532\t65532\t65532\n"},
		{
			name:     "no-gid",
			status:   "Uid:\t0\t0\t0\t0\n",
			wantCode: 1,
			want:     "Uid:\t0\t0\t0\t0\n" + record(false, "user completed", "no exception", "/proc/1/status has no well-formed Gid line"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			code, stdout, _ := probe(t, testEnv(t, fstest.MapFS{"1/status": file(tt.status)}, ""), "user")
			if code != tt.wantCode || stdout != tt.want {
				t.Errorf("user = exit %d, stdout %q; want exit %d, stdout %q", code, stdout, tt.wantCode, tt.want)
			}
		})
	}
}

func TestAssertCaps(t *testing.T) {
	t.Parallel()

	allClear := record(true, "CapEff, every capability bit clear", "0000000000000000", "0000000000000000") +
		record(true, "CapPrm, every capability bit clear", "0000000000000000", "0000000000000000") +
		record(true, "CapInh, every capability bit clear", "0000000000000000", "0000000000000000") +
		record(true, "CapBnd, every capability bit clear", "0000000000000000", "0000000000000000") +
		record(true, "CapAmb, every capability bit clear", "0000000000000000", "0000000000000000")
	tests := []struct {
		name     string
		status   string
		wantCode int
		want     string
	}{
		{name: "none", status: status, want: allClear},
		{
			// --cap-add reaches CapBnd alone: exec clears CapEff and CapPrm
			// for uid 65532 whatever the engine grants.
			name:     "a-capability-added",
			status:   strings.Replace(status, "CapBnd:\t0000000000000000", "CapBnd:\t00000000a80425fb", 1),
			wantCode: 1,
			want: strings.Replace(allClear,
				record(true, "CapBnd, every capability bit clear", "0000000000000000", "0000000000000000"),
				record(false, "CapBnd, every capability bit clear", "0000000000000000", "00000000a80425fb"), 1),
		},
		{
			name:     "a-set-missing",
			status:   "CapEff:\t0000000000000000\n",
			wantCode: 1,
			want: record(true, "CapEff, every capability bit clear", "0000000000000000", "0000000000000000") +
				record(false, "assert-caps completed", "no exception", "/proc/1/status has no well-formed CapPrm line"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			code, stdout, _ := probe(t, testEnv(t, fstest.MapFS{"1/status": file(tt.status)}, ""), "assert-caps")
			if code != tt.wantCode || stdout != tt.want {
				t.Errorf("assert-caps = exit %d, stdout %q; want exit %d, stdout %q", code, stdout, tt.wantCode, tt.want)
			}
		})
	}
}
