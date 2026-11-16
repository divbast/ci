// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Command core is the core probe divbast's harness runs inside a
// container: the subcommands every contract check shares, about PID 1,
// the filesystem and the network. It is built static, for the image's
// architecture, and mounted read-only at /divbast/probe/core, so it needs
// nothing in the image.
//
// Usage:
//
//	core <subcommand> [arguments]
//
// It prints one record per assertion, as probekit's package comment
// gives them. Its exit status is 0 when every record is ok, 1 when any
// is FAIL, and 2 for a subcommand or arguments it does not know.
package main

import (
	"context"
	"os"

	"github.com/divbast/ci/harness/internal/coreprobe"
)

func main() {
	os.Exit(coreprobe.Main(context.Background(), coreprobe.HostEnv(), os.Args[1:], os.Stdout, os.Stderr))
}
