// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package harness

import (
	"bytes"
	"context"
	_ "embed" // for coreProbe
	"fmt"
	"path"
	"slices"
	"strings"
	"time"
)

// FrankenPHP is the PHP every divbast image runs, and so the probe's.
const FrankenPHP = "/usr/local/bin/frankenphp"

// ProbeDir is where [InstallProbe] puts the probe inside a container: on
// /tmp, the one place the contract lets a container write.
const ProbeDir = "/tmp/divbast-probe"

// coreProbe is probe/core.php, the subcommands every app shares.
//
//go:embed probe/core.php
var coreProbe []byte

// Probe is the probe installed in one container.
type Probe struct {
	c *Container
}

// InstallProbe writes the core probe into c at ProbeDir, and app, when it
// is not empty, beside it as app.php: PHP returning the app's own
// subcommands, which core.php merges after its own.
//
// Each file goes in on stdin and the container's own PHP writes it out,
// since `cp` refuses a container whose root is read-only, and a container
// with no volume has nowhere else to put it.
func InstallProbe(ctx context.Context, c *Container, app []byte) (*Probe, error) {
	if err := install(ctx, c, path.Join(ProbeDir, "core.php"), coreProbe); err != nil {
		return nil, err
	}
	if len(app) > 0 {
		if err := install(ctx, c, path.Join(ProbeDir, "app.php"), app); err != nil {
			return nil, err
		}
	}
	return &Probe{c: c}, nil
}

// An engine can refuse an exec while a container is starting: Docker once
// answered "cannot exec in a stopped container" here, with exit status
// 128, to one whose server was still coming up. So an exec the engine
// itself failed, rather than the PHP it ran, is tried again while the
// container runs, up to installAttempts times, installRetry apart.
const (
	installAttempts = 5
	installRetry    = 500 * time.Millisecond
)

// engineFailed reports whether an exec that exited as res did failed in
// the engine rather than in the PHP it ran: 125 for the engine, 126 and
// 127 for a command it could not run, and 128 where Docker's runtime
// refused. Podman also exits 255 when its runtime fails the exec, as crun
// once did with "setns `mnt`: Bad file descriptor" into a running
// container, and then opens stderr with podmanRuntimeError, which no PHP
// prints. Any other exit is the PHP's, which exits 0 or 1 for the install,
// or 255 for a fatal error, and would only do the same again.
func engineFailed(res Result) bool {
	return res.Code >= 125 && res.Code <= 128 ||
		res.Code == 255 && bytes.HasPrefix(res.Stderr, []byte(podmanRuntimeError))
}

// podmanRuntimeError opens what Podman prints when its OCI runtime fails.
const podmanRuntimeError = "Error: OCI runtime error:"

func install(ctx context.Context, c *Container, file string, body []byte) error {
	for attempt := 1; ; attempt++ {
		res, err := c.Exec(ctx, bytes.NewReader(body), FrankenPHP, "php-cli", "-r", installCode(file))
		if err != nil {
			return err
		}
		if res.Code == 0 {
			return nil
		}
		failed := fmt.Errorf("installing %s in container %s: exit status %d: %s", file, c, res.Code, combined(res))
		if !engineFailed(res) || attempt == installAttempts {
			return failed
		}
		ins, err := c.Inspect(ctx)
		if err != nil {
			return fmt.Errorf("%w; and then: %w", failed, err)
		}
		if !ins.State.Running {
			return failed
		}
		if err := sleep(ctx, installRetry); err != nil {
			return err
		}
	}
}

// installCode is PHP that writes its stdin to file, making the directory
// first, and says why on stderr when it cannot.
func installCode(file string) string {
	return `$f = ` + phpString(file) + `; $d = dirname($f);
if (!is_dir($d) && !@mkdir($d, 0700, true)) {
    fwrite(STDERR, "cannot make $d: " . (error_get_last()['message'] ?? 'no reason given') . "\n");
    exit(1);
}
$s = stream_get_contents(STDIN);
if ($s === false || @file_put_contents($f, $s) !== strlen($s)) {
    fwrite(STDERR, "cannot write $f: " . (error_get_last()['message'] ?? 'no reason given') . "\n");
    exit(1);
}`
}

// phpString quotes s as a single-quoted PHP string.
func phpString(s string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) + "'"
}

// Output runs one probe subcommand and returns what it printed, for the
// subcommands that print what they read rather than records.
func (p *Probe) Output(ctx context.Context, sub string, args ...string) (Result, error) {
	return p.c.Exec(ctx, nil, slices.Concat([]string{FrankenPHP, "php-cli", path.Join(ProbeDir, "core.php"), sub}, args)...)
}

// Record is one assertion the probe made.
type Record struct {
	OK                    bool
	What, Expected, Found string
}

// Run runs one probe subcommand and returns its records. A FAIL among them
// is no error: [Checks.Records] reports it. The error is for a subcommand
// that could not be run, printed something other than records, printed
// none, or exited with a status its records do not bear out.
func (p *Probe) Run(ctx context.Context, sub string, args ...string) ([]Record, error) {
	res, err := p.Output(ctx, sub, args...)
	if err != nil {
		return nil, err
	}
	what := fmt.Sprintf("probe %s in container %s", sub, p.c)
	records, err := parseRecords(res.Stdout)
	switch {
	case err != nil:
		return nil, fmt.Errorf("%s: %w; stderr: %s", what, err, bytes.TrimSpace(res.Stderr))
	case res.Code != 0 && res.Code != 1:
		return nil, fmt.Errorf("%s: exit status %d: %s", what, res.Code, combined(res))
	case len(records) == 0:
		return nil, fmt.Errorf("%s printed no records, exit status %d: %s", what, res.Code, combined(res))
	}
	if failed := slices.ContainsFunc(records, func(r Record) bool { return !r.OK }); failed != (res.Code == 1) {
		return nil, fmt.Errorf("%s exited %d, which disagrees with its records:\n%s", what, res.Code, res.Stdout)
	}
	return records, nil
}

// parseRecords reads the probe's records, one per line: ok or FAIL, what,
// expected and found, separated by tabs.
func parseRecords(out []byte) ([]Record, error) {
	var records []Record
	n := 0
	for line := range strings.Lines(string(out)) {
		n++
		line = strings.TrimSuffix(line, "\n")
		if line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 4 || (f[0] != "ok" && f[0] != "FAIL") {
			return nil, fmt.Errorf("line %d is not a record: %q", n, line)
		}
		records = append(records, Record{OK: f[0] == "ok", What: f[1], Expected: f[2], Found: f[3]})
	}
	return records, nil
}

// combined returns a command's stdout then its stderr, trimmed, for an
// error.
func combined(res Result) string {
	return strings.TrimSpace(string(res.Stdout) + string(res.Stderr))
}
