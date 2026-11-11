// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package harness

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// CheckLogEnv names the environment variable that, when it is set, holds
// the path of a file each check's name is appended to, one per line,
// whether it passes or not. It is how a suite ported from bash shows it
// still makes every check the bash suite made.
const CheckLogEnv = "DIVBAST_CHECK_LOG"

// Checks reports named checks through a test: an ok line in its log for
// one that passes, and a failure, which does not stop the test, for one
// that does not.
type Checks struct {
	tb  testing.TB
	log string
}

// NewChecks returns Checks that report through tb, and name each check in
// the file $DIVBAST_CHECK_LOG holds, if it is set.
func NewChecks(tb testing.TB) *Checks {
	tb.Helper()
	return newChecks(tb, os.Getenv(CheckLogEnv))
}

func newChecks(tb testing.TB, log string) *Checks {
	tb.Helper()
	return &Checks{tb: tb, log: log}
}

// Records reports each of the probe's records as a check of its own,
// named by its What. No records at all is a failure: a probe that
// asserted nothing proves nothing.
func (c *Checks) Records(records []Record) {
	c.tb.Helper()
	if len(records) == 0 {
		c.tb.Errorf("FAIL no records to check: a probe that asserted nothing proves nothing")
		return
	}
	for _, r := range records {
		c.note(r.What)
		if r.OK {
			c.tb.Logf("ok   %s (%s)", r.What, r.Found)
		} else {
			c.tb.Errorf("FAIL %s: got %q, want %q", r.What, r.Found, r.Expected)
		}
	}
}

// Equal checks that got is want. Only an exact match passes: a status
// check that took any 2xx would pass an exception page served with 200.
func Equal[T comparable](c *Checks, what string, want, got T) {
	c.tb.Helper()
	c.note(what)
	if got == want {
		c.tb.Logf("ok   %s (%s)", what, show(got))
		return
	}
	c.tb.Errorf("FAIL %s: got %s, want %s", what, show(got), show(want))
}

// True checks that ok holds. detail says what was found, in either case.
func (c *Checks) True(what string, ok bool, detail string) {
	c.tb.Helper()
	c.note(what)
	if ok {
		c.tb.Logf("ok   %s (%s)", what, detail)
		return
	}
	c.tb.Errorf("FAIL %s: %s", what, detail)
}

// show formats a checked value, quoting a string so that white space and
// emptiness show.
func show(v any) string {
	if s, ok := v.(string); ok {
		return strconv.Quote(s)
	}
	return fmt.Sprint(v)
}

// logMu keeps this process's appends to the check log apart. Each name
// goes out in one write to a file opened to append, which the kernel keeps
// whole against another process's appends too.
var logMu sync.Mutex

// note names a check in the check log, if there is one. A log it cannot
// write fails the test: a parity check that read a short log would pass
// for the wrong reason.
func (c *Checks) note(what string) {
	c.tb.Helper()
	if c.log == "" {
		return
	}
	line := []byte(oneLine(what) + "\n")

	logMu.Lock()
	defer logMu.Unlock()
	f, err := os.OpenFile(c.log, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		c.tb.Errorf("%s: %v", CheckLogEnv, err)
		return
	}
	_, werr := f.Write(line)
	if err := errors.Join(werr, f.Close()); err != nil {
		c.tb.Errorf("%s: %v", CheckLogEnv, err)
	}
}

// oneLine puts a check's name on one line, as the probe does a record's
// fields.
func oneLine(s string) string {
	return strings.TrimSpace(strings.NewReplacer("\t", " ", "\n", " ", "\r", " ").Replace(s))
}
