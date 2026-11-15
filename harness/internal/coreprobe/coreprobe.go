// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Package coreprobe is the core probe's subcommands: what the contract's
// checks assert from inside a container, about PID 1, the filesystem and
// the network. harness/probe/core is the binary over them, which the
// harness mounts into every container it starts for a check, read-only,
// so it needs nothing in the image at all. It speaks
// [github.com/divbast/ci/harness/probekit]'s records.
//
// Every subcommand reads the container through an [Env], so a test can
// give it a /proc and a root of its own.
package coreprobe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/divbast/ci/harness/probekit"
)

// Env is what the probe reads the container through.
type Env struct {
	// Proc is the kernel's /proc.
	Proc fs.FS
	// Root is the container's "/", which every path a subcommand takes,
	// or checks, is under.
	Root string
	// Dial makes an outbound connection, as net.Dialer.DialContext does.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// Access is access(2): whether the probe's user may use path as mode
	// asks.
	Access func(path string, mode uint32) error
}

// HostEnv returns the Env of the container the probe runs in.
func HostEnv() *Env {
	return &Env{
		Proc:   os.DirFS("/proc"),
		Root:   "/",
		Dial:   (&net.Dialer{}).DialContext,
		Access: syscall.Access,
	}
}

// Commands returns the core probe's subcommands over env.
func Commands(env *Env) map[string]probekit.Command {
	return map[string]probekit.Command{
		"assert-pid1":      {Args: []string{"argv"}, Variadic: true, Run: env.assertPID1},
		"assert-caps":      {Run: env.assertCaps},
		"assert-no-shell":  {Run: env.assertNoShell},
		"assert-read-only": {Run: env.assertReadOnly},
		"assert-listeners": {Args: []string{"tcp-port"}, Variadic: true, Run: env.assertListeners},
		"probe-egress":     {Run: env.probeEgress},
		"user":             {Run: env.user},
		"http-request":     {Args: []string{"method", "url", "headers", "body"}, Run: httpRequest},
		"parse-listeners":  {Args: []string{"tcp-table", "udp-table", "fd-targets"}, Run: parseListeners},
		"is-file":          {Args: []string{"path"}, Run: env.isFile},
	}
}

// Main runs the subcommand args names, in env, and returns its exit
// status, as [probekit.Main] does.
func Main(ctx context.Context, env *Env, args []string, stdout, stderr io.Writer) int {
	return probekit.Main(ctx, Commands(env), args, stdout, stderr)
}

// readProc returns the file name under /proc, or an error naming it.
func (env *Env) readProc(name string) (string, error) {
	b, err := fs.ReadFile(env.Proc, name)
	if err != nil {
		return "", fmt.Errorf("cannot read /proc/%s", name)
	}
	return string(b), nil
}

// path returns p, a path inside the container, as the probe reaches it.
func (env *Env) path(p string) string {
	return strings.TrimSuffix(env.Root, "/") + "/" + strings.TrimPrefix(p, "/")
}

// errnoText returns the errno err carries, as C's strerror words it:
// "Permission denied", where Go's is "permission denied". An error that
// carries none is its own text.
func errnoText(err error) string {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return err.Error()
	}
	s := errno.Error()
	r, n := utf8.DecodeRuneInString(s)
	return strings.ToUpper(string(r)) + s[n:]
}

// jsonList returns words as a JSON array, as PHP's json_encode writes one
// with slashes unescaped and bytes that are not UTF-8 replaced: every
// other character past ASCII as \u escapes.
func jsonList(words []string) string {
	var b strings.Builder
	b.WriteByte('[')
	for i, w := range words {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('"')
		for _, r := range w {
			switch {
			case r == '"' || r == '\\':
				b.WriteByte('\\')
				b.WriteRune(r)
			case r == '\b':
				b.WriteString(`\b`)
			case r == '\f':
				b.WriteString(`\f`)
			case r == '\n':
				b.WriteString(`\n`)
			case r == '\r':
				b.WriteString(`\r`)
			case r == '\t':
				b.WriteString(`\t`)
			case r < 0x20 || (r > 0x7f && r <= 0xffff):
				fmt.Fprintf(&b, `\u%04x`, r)
			case r > 0xffff:
				r -= 0x10000
				fmt.Fprintf(&b, `\u%04x\u%04x`, 0xd800+(r>>10), 0xdc00+(r&0x3ff))
			default:
				b.WriteRune(r)
			}
		}
		b.WriteByte('"')
	}
	b.WriteByte(']')
	return b.String()
}
