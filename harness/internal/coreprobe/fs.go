// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package coreprobe

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"syscall"

	"github.com/divbast/ci/harness/probekit"
)

// forbiddenShells are the shells most likely to be the target of an
// intrusion.
var forbiddenShells = []string{"/bin/sh", "/bin/bash", "/bin/dash"}

const (
	present = "present"
	absent  = "absent"
	// rootWriteProbe is the file assert-read-only tries to create.
	rootWriteProbe = "/.divbast-write-probe"
	// readOnlyError is EROFS, as strerror words it.
	readOnlyError = "Read-only file system"
)

// presence says whether anything is at p, a path inside the container:
// present, absent, or why the probe cannot tell. Only a lookup that fails
// because nothing is there, ENOENT or ENOTDIR, proves the path absent.
// One the probe may not make, as through a directory only root may
// search, proves nothing: whatever is there is still there for root.
func (env *Env) presence(p string) string {
	_, err := os.Lstat(env.path(p))
	if err == nil {
		return present
	}
	var errno syscall.Errno
	switch {
	case !errors.As(err, &errno):
		return fmt.Sprintf("not looked up (%v), so it may be there", err)
	case errno == syscall.ENOENT || errno == syscall.ENOTDIR:
		return absent
	default:
		return fmt.Sprintf("not looked up (errno %d: %s), so it may be there", int(errno), errnoText(errno))
	}
}

// assertNoShell checks that no shell is in the image.
func (env *Env) assertNoShell(_ context.Context, out *probekit.Output, _ []string) error {
	for _, p := range forbiddenShells {
		found := env.presence(p)
		out.Record(found == absent, p+" is absent from the image", absent, found)
	}
	return nil
}

// assertReadOnly checks that creating a file at the root fails because
// the root is read-only. The kernel answers a create on a read-only mount
// with EROFS before it checks permissions on the directory, so the error
// names the mount. A root that was merely owned by root would answer
// "Permission denied" instead, and this would fail.
func (env *Env) assertReadOnly(_ context.Context, out *probekit.Output, _ []string) error {
	const body = "probe\n"
	p := env.path(rootWriteProbe)
	err := os.WriteFile(p, []byte(body), 0o600)
	found := "wrote " + strconv.Itoa(len(body)) + " bytes"
	if err == nil {
		_ = os.Remove(p)
	} else {
		found = "cannot write " + rootWriteProbe + ": " + errnoText(err)
	}
	out.Record(err != nil && errnoText(err) == readOnlyError,
		"writing "+rootWriteProbe+" fails because / is read-only", readOnlyError, found)
	return nil
}

// isFile prints present or absent, as anything is at path or not, for
// the container's user. A lookup it may not make counts as present, as
// [Env.presence] says why.
func (env *Env) isFile(_ context.Context, out *probekit.Output, args []string) error {
	found := env.presence(args[0])
	if found != absent {
		found = present
	}
	_, err := fmt.Fprintln(out, found)
	return err
}
