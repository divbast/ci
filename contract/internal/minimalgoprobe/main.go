// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Command minimalgoprobe is the Go fixture's own probe, which the
// harness builds and mounts beside the core one, as an app's would be:
// it shows a Go app probe reaches the app from inside its container.
//
// Usage:
//
//	minimalgoprobe assert-page
//
// It prints one record, as probekit's package comment gives them, and
// exits 0 when it is ok, 1 when it is not, and 2 for a subcommand or
// arguments it does not know.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/divbast/ci/harness/probekit"
)

func main() {
	os.Exit(probekit.Main(context.Background(), map[string]probekit.Command{
		"assert-page": {Run: assertPage},
	}, os.Args[1:], os.Stdout, os.Stderr))
}

// assertPage checks the app port answers GET / with the fixture's page.
func assertPage(ctx context.Context, out *probekit.Output, _ []string) error {
	resp, err := probekit.Request(ctx, "GET", "http://127.0.0.1:8080/", nil, "")
	if err != nil {
		return err
	}
	out.Equal("GET / answers the fixture's page", "200 minimal", fmt.Sprintf("%d %s", resp.Status, resp.Body))
	return nil
}
