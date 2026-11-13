// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package harness

import (
	"fmt"
	"strings"
	"testing"
)

// The assertions below each report through [NewChecks]: an ok line for a
// record that holds, and a failure, which does not stop the test, for one
// that does not, each named by the what it was given, and named in the
// check log too when $DIVBAST_CHECK_LOG is set. Each that needs a context
// takes tb's.

// StatusIs checks that GET path, sent to s from the host, answers want:
// exactly want, since an exception page served with 200 passes any check
// that takes a 2xx.
func StatusIs(tb testing.TB, s *Serving, what string, want int, path string) {
	tb.Helper()
	resp, err := s.Get(tb.Context(), path, nil)
	Answers(tb, what, want, resp, err)
}

// Answers checks that a request got an answer, as err says, and that its
// status is exactly want.
func Answers(tb testing.TB, what string, want int, resp Response, err error) {
	tb.Helper()
	checks := NewChecks(tb)
	if err != nil {
		checks.True(what, false, err.Error())
		return
	}
	Equal(checks, what, want, resp.Status)
}

// Contains checks that text holds needle.
func Contains(tb testing.TB, what, needle, text string) {
	tb.Helper()
	ok := strings.Contains(text, needle)
	detail := fmt.Sprintf("holds %q", needle)
	if !ok {
		detail = fmt.Sprintf("%q is not in %s", needle, Clip(text))
	}
	NewChecks(tb).True(what, ok, detail)
}

// Lacks checks that text does not hold needle. An empty text lacks
// anything, which shows nothing, so it fails rather than passes.
func Lacks(tb testing.TB, what, needle, text string) {
	tb.Helper()
	ok := text != "" && !strings.Contains(text, needle)
	var detail string
	switch {
	case text == "":
		detail = "there is nothing to look through"
	case ok:
		detail = fmt.Sprintf("no %q in %d bytes", needle, len(text))
	default:
		detail = fmt.Sprintf("%q is in %s", needle, Clip(text))
	}
	NewChecks(tb).True(what, ok, detail)
}

// LogContains checks that c's log holds needle, as [Contains] does.
func LogContains(tb testing.TB, c *Container, what, needle string) {
	tb.Helper()
	if logs, ok := logOf(tb, c, what); ok {
		Contains(tb, what, needle, logs)
	}
}

// LogLacks checks that c's log does not hold needle, as [Lacks] does.
func LogLacks(tb testing.TB, c *Container, what, needle string) {
	tb.Helper()
	if logs, ok := logOf(tb, c, what); ok {
		Lacks(tb, what, needle, logs)
	}
}

// logOf returns c's log, or fails the check what with why it could not be
// read.
func logOf(tb testing.TB, c *Container, what string) (string, bool) {
	tb.Helper()
	logs, err := c.Logs(tb.Context())
	if err != nil {
		NewChecks(tb).True(what, false, err.Error())
		return "", false
	}
	return logs, true
}

// The two answers [IsFile] takes, for a path that is in a container and
// one that is not.
const (
	present = "present"
	absent  = "absent"
)

// IsFile checks that path is in c or not, as want says: "present" or
// "absent". It asks c's own PHP, with file_exists, which finds a path
// whatever it is, a file or a directory, that the container's user may
// look up.
func IsFile(tb testing.TB, c *Container, what, want, path string) {
	tb.Helper()
	checks := NewChecks(tb)
	if want != present && want != absent {
		checks.True(what, false, fmt.Sprintf("want is %q, and a path is %s or %s", want, present, absent))
		return
	}
	got, err := PHPIn(tb.Context(), c, fileStateCode(path))
	if err != nil {
		checks.True(what, false, err.Error())
		return
	}
	Equal(checks, what, want, got)
}

// fileStateCode is PHP that prints present or absent, as path is in the
// container or not. The path goes in single-quoted, so nothing in it is
// interpolated.
func fileStateCode(path string) string {
	return fmt.Sprintf(`echo file_exists(%s) ? %q : %q;`, phpString(path), present, absent)
}

// RunRecords runs the probe subcommand sub in p, with args, and reports
// each of its records as a check of its own, named by its What. A
// subcommand that could not be run, or printed no records, fails the
// test, as does a nil p: a probe never installed.
func RunRecords(tb testing.TB, p *Probe, sub string, args ...string) {
	tb.Helper()
	if p == nil {
		tb.Errorf("FAIL probe %s: no probe is installed", sub)
		return
	}
	records, err := p.Run(tb.Context(), sub, args...)
	if err != nil {
		tb.Errorf("FAIL %v", err)
		return
	}
	NewChecks(tb).Records(records)
}

// Refuses runs spec and checks that the container refuses to start: that
// it exits with exactly wantExit within ServeWithin, and that its log
// holds needle. Each is a record of its own, named
// "<what>: the container exits" and "<what>: the log says '<needle>'".
// One that exits with any other status, 0 or not, fails, with the status
// it found and the container's log. spec runs as it is given: a refusal
// comes before there is a server to reach, so a Network of "none" suits
// most.
func Refuses(tb testing.TB, e Engine, spec *RunSpec, wantExit int, what, needle string) {
	tb.Helper()
	ctx := tb.Context()
	checks := NewChecks(tb)
	exits, says := what+": the container exits", fmt.Sprintf("%s: the log says '%s'", what, needle)

	c, err := e.Start(ctx, tb, spec)
	if err != nil {
		checks.True(exits, false, err.Error())
		checks.True(says, false, err.Error())
		return
	}
	code, werr := c.WaitExit(ctx, ServeWithin)
	logs, lerr := c.Logs(ctx)
	logged := "its log: " + Clip(logs)
	if lerr != nil {
		logged = "its log could not be read: " + lerr.Error()
	}
	switch {
	case werr != nil:
		checks.True(exits, false, werr.Error()+"; "+logged)
	case code != wantExit:
		checks.True(exits, false, fmt.Sprintf("exit status %d, want %d; %s", code, wantExit, logged))
	default:
		checks.True(exits, true, fmt.Sprintf("exit status %d", code))
	}
	if lerr != nil {
		checks.True(says, false, lerr.Error())
		return
	}
	Contains(tb, says, needle, logs)
}

// clipAt is as much of a text as Clip quotes.
const clipAt = 600

// Clip quotes text for a check's detail, as %q quotes it, so that white
// space and emptiness show: the whole of it up to 600 bytes, and past
// that its first 600, then how many bytes the whole held.
func Clip(text string) string {
	if len(text) <= clipAt {
		return fmt.Sprintf("%q", text)
	}
	return fmt.Sprintf("%q... (%d bytes)", text[:clipAt], len(text))
}
