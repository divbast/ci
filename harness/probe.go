// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package harness

import (
	"bytes"
	"context"
	_ "embed" // for phpProbe
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
)

// ProbeMount is where the probe volume is mounted, read-only, in every
// container started with a [RunSpec.Probe]: CoreProbePath is the core
// probe, and AppProbePath the app's own Go probe, when it has one.
const (
	ProbeMount    = "/divbast/probe"
	CoreProbePath = ProbeMount + "/core"
	AppProbePath  = ProbeMount + "/app"
)

// PHPProbeDir is where [AttachProbe] writes a PHP app's probe, through the
// app's own PHP: probe.php and the app's app.php beside it, on /tmp, the
// one place the contract lets a container write.
const PHPProbeDir = "/tmp/divbast-probe"

// phpProbe is probe/php/probe.php, which runs a PHP app's own
// subcommands.
//
//go:embed probe/php/probe.php
var phpProbe []byte

// PHPProbe is a PHP app's own probe subcommands, which run under the
// app's own PHP.
type PHPProbe struct {
	// Binary is the app's PHP, as an absolute path, run as
	// "<Binary> php-cli": FrankenPHP's, as /usr/local/bin/frankenphp.
	Binary string
	// Probe is the app's app.php: PHP returning its subcommands.
	Probe []byte
}

// ProbeSpec asks for the probe in a container: the core probe always,
// and the app's own subcommands, in Go, PHP or both.
type ProbeSpec struct {
	// AppPackage is a Go main package of the module under test, as go build
	// takes it from the module's root, such as "./test/probe": the app's
	// own probe, built and mounted beside the core one. Empty for none.
	AppPackage string
	// PHP is a PHP app's own probe, nil for none.
	PHP *PHPProbe
}

// Probe is the probe in one container.
type Probe struct {
	c    *Container
	spec ProbeSpec
}

// AttachProbe returns the probe in c, which must have been started with
// a [RunSpec.Probe]: the core probe, and any Go app probe, are on its
// read-only mount already. A PHP app probe is written into c's /tmp
// first, at PHPProbeDir, as it must be again after a restart empties
// /tmp. Each file goes in on stdin and the app's own PHP writes it out,
// since `cp` refuses a container whose root is read-only.
func AttachProbe(ctx context.Context, c *Container) (*Probe, error) {
	if c.probe == nil {
		return nil, fmt.Errorf("container %s was started without the probe: set RunSpec.Probe to mount it", c)
	}
	if php := c.probe.PHP; php != nil {
		if err := install(ctx, c, php.Binary, path.Join(PHPProbeDir, "probe.php"), phpProbe); err != nil {
			return nil, err
		}
		if err := install(ctx, c, php.Binary, path.Join(PHPProbeDir, "app.php"), php.Probe); err != nil {
			return nil, err
		}
	}
	return &Probe{c: c, spec: *c.probe}, nil
}

// install writes body to file in c, through binary's PHP. An exec the
// engine refuses is tried again by [Container.Exec], so a container still
// starting gets the file all the same.
func install(ctx context.Context, c *Container, binary, file string, body []byte) error {
	res, err := c.Exec(ctx, bytes.NewReader(body), binary, "php-cli", "-r", installCode(file))
	if err != nil {
		return fmt.Errorf("installing %s: %w", file, err)
	}
	if res.Code != 0 {
		return fmt.Errorf("installing %s in container %s: exit status %d: %s", file, c, res.Code, combined(res))
	}
	return nil
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

// Output runs one core probe subcommand and returns what it printed, for
// the subcommands that print what they read rather than records.
func (p *Probe) Output(ctx context.Context, sub string, args ...string) (Result, error) {
	return p.c.Exec(ctx, nil, slices.Concat([]string{CoreProbePath, sub}, args)...)
}

// Run runs one core probe subcommand and returns its records. A FAIL
// among them is no error: [Checks.Records] reports it. The error is for
// a subcommand that could not be run, printed something other than
// records, printed none, or exited with a status its records do not bear
// out.
func (p *Probe) Run(ctx context.Context, sub string, args ...string) ([]Record, error) {
	return p.records(ctx, sub, p.Output, args)
}

// errNoAppProbe means a probe was asked for app subcommands of a kind its
// container was not started with.
var errNoAppProbe = errors.New("no such app probe")

// OutputApp runs one subcommand of the app's Go probe and returns what it
// printed. It is an error unless the container's probe has an AppPackage.
func (p *Probe) OutputApp(ctx context.Context, sub string, args ...string) (Result, error) {
	if p.spec.AppPackage == "" {
		return Result{}, fmt.Errorf("container %s: %w: its probe has no Go app probe, so set ProbeSpec.AppPackage", p.c, errNoAppProbe)
	}
	return p.c.Exec(ctx, nil, slices.Concat([]string{AppProbePath, sub}, args)...)
}

// RunApp runs one subcommand of the app's Go probe and returns its
// records, as [Probe.Run] does.
func (p *Probe) RunApp(ctx context.Context, sub string, args ...string) ([]Record, error) {
	return p.records(ctx, sub, p.OutputApp, args)
}

// OutputPHP runs one of a PHP app's own subcommands, under the app's PHP,
// and returns what it printed. It is an error unless the container's
// probe has PHP.
func (p *Probe) OutputPHP(ctx context.Context, sub string, args ...string) (Result, error) {
	if p.spec.PHP == nil {
		return Result{}, fmt.Errorf("container %s: %w: its probe has no PHP app probe, so set ProbeSpec.PHP", p.c, errNoAppProbe)
	}
	return p.c.Exec(ctx, nil, slices.Concat([]string{p.spec.PHP.Binary, "php-cli", path.Join(PHPProbeDir, "probe.php"), sub}, args)...)
}

// RunPHP runs one of a PHP app's own subcommands and returns its records,
// as [Probe.Run] does.
func (p *Probe) RunPHP(ctx context.Context, sub string, args ...string) ([]Record, error) {
	return p.records(ctx, sub, p.OutputPHP, args)
}

// records runs sub through output and reads its records.
func (p *Probe) records(ctx context.Context, sub string, output func(context.Context, string, ...string) (Result, error), args []string) ([]Record, error) {
	res, err := output(ctx, sub, args...)
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

// Record is one assertion the probe made.
type Record struct {
	OK                    bool
	What, Expected, Found string
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
