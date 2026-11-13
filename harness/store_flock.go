// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package harness

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
)

// fileLocks says whether lockFile locks a file that other processes see.
const fileLocks = true

// lockFile locks the file at path with flock, shared or, with exclusive
// set, exclusive, making it if need be, and waits for any process holding
// it the other way, looking again every storePoll, until it can or ctx is
// done. Closing the file it returns releases the lock, as does the
// process ending, however it ends.
func lockFile(ctx context.Context, path string, exclusive bool) (*os.File, error) {
	// Not through os.Root: in Go 1.27.4, of two of its OpenFile calls that
	// make the same file at once, one can fail with "no such file or
	// directory", and every build in a suite opens this file at once.
	// open(2) with O_CREAT makes it once, whoever comes first. The path is
	// the harness's own, never input.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // G304: the harness's own lock file, as above
	if err != nil {
		return nil, err
	}
	how := syscall.LOCK_SH
	if exclusive {
		how = syscall.LOCK_EX
	}
	for {
		err := flock(f, how|syscall.LOCK_NB)
		switch {
		case err == nil:
			return f, nil
		case !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR):
			return nil, errors.Join(fmt.Errorf("lock %s: %w", path, err), f.Close())
		}
		if err := Pause(ctx, storePoll); err != nil {
			return nil, errors.Join(err, f.Close())
		}
	}
}

// flock runs flock(2) on f with how.
func flock(f *os.File, how int) error {
	conn, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var lockErr error
	if err := conn.Control(func(fd uintptr) { lockErr = syscall.Flock(int(fd), how) }); err != nil {
		return err
	}
	return lockErr
}
