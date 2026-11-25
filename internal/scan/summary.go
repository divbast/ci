// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package scan

import (
	"fmt"
	"iter"
	"strings"
)

// String returns f as the scan lists it: the advisory, its severity, the
// package and the version installed, the fix or that there is none, and
// where it was found.
func (f Finding) String() string {
	fix := ", no fix"
	if f.Fixed != "" {
		fix = ", fixed in " + f.Fixed
	}
	return f.ID + " " + f.Severity + " " + f.Pkg + " " + f.Version + fix + ", " + f.Where
}

// Listing returns what the scan prints: what it compared with, then how
// many findings the published image lacks, under verdict, and each of
// them, then those of them with no severity, and those held for each
// Hold, when there are any, then how many it has, and each of those.
func Listing(against, verdict string, s *Split) string {
	var b strings.Builder
	fmt.Fprintf(&b, "compared with %s\n", against)
	fmt.Fprintf(&b, "%d %s:\n", len(s.New), verdict)
	for i := range s.New {
		fmt.Fprintf(&b, "  %s\n", &s.New[i])
	}
	if len(s.Listed) > 0 {
		fmt.Fprintf(&b, "%d new with no severity, so listed, not blocking:\n", len(s.Listed))
		for i := range s.Listed {
			fmt.Fprintf(&b, "  %s\n", &s.Listed[i])
		}
	}
	for hold, fs := range held(s.Held) {
		fmt.Fprintf(&b, "%d new %s, so listed, not blocking:\n", len(fs), hold)
		for i := range fs {
			fmt.Fprintf(&b, "  %s\n", &fs[i])
		}
	}
	fmt.Fprintf(&b, "%d already published, so advisory:\n", len(s.Old))
	for i := range s.Old {
		fmt.Fprintf(&b, "  %s\n", &s.Old[i])
	}
	return b.String()
}

// Summary returns the Markdown the scan appends to the run's summary page
// for arch: what it compared with, warning as a callout unless it is
// empty, then a table of the findings the published image lacks, under
// heading, then one of those of them with no severity, and one of those
// held for each Hold, when there are any, and one of those it has.
func Summary(arch, against, heading, warning string, s *Split) string {
	var b strings.Builder
	fmt.Fprintf(&b, "### Vulnerability scan, %s\n\n", arch)
	fmt.Fprintf(&b, "Compared with `%s`.\n\n", against)
	if warning != "" {
		fmt.Fprintf(&b, "> **Warning:** %s\n\n", warning)
	}
	fmt.Fprintf(&b, "**%s: %d**\n\n", heading, len(s.New))
	table(&b, s.New)
	if len(s.Listed) > 0 {
		fmt.Fprintf(&b, "\n**New with no severity, so listed, not blocking: %d**\n\n", len(s.Listed))
		table(&b, s.Listed)
	}
	for hold, fs := range held(s.Held) {
		fmt.Fprintf(&b, "\n**New %s, so listed, not blocking: %d**\n\n", hold, len(fs))
		table(&b, fs)
	}
	fmt.Fprintf(&b, "\n**Already published, so advisory: %d**\n\n", len(s.Old))
	table(&b, s.Old)
	b.WriteString("\n")
	return b.String()
}

// held yields findings by their Hold, each Hold once, in the order it
// first appears, with its findings in theirs.
func held(findings []Finding) iter.Seq2[string, []Finding] {
	return func(yield func(string, []Finding) bool) {
		var holds []string
		by := map[string][]Finding{}
		for i := range findings {
			f := &findings[i]
			if _, ok := by[f.Hold]; !ok {
				holds = append(holds, f.Hold)
			}
			by[f.Hold] = append(by[f.Hold], *f)
		}
		for _, h := range holds {
			if !yield(h, by[h]) {
				return
			}
		}
	}
}

func table(b *strings.Builder, findings []Finding) {
	if len(findings) == 0 {
		b.WriteString("None.\n")
		return
	}
	b.WriteString("| Vulnerability | Severity | Package | Installed | Fixed in | Where |\n")
	b.WriteString("|---|---|---|---|---|---|\n")
	for i := range findings {
		f := &findings[i]
		id := f.ID
		if f.URL != "" {
			id = "[" + f.ID + "](" + f.URL + ")"
		}
		fixed := "no fix"
		if f.Fixed != "" {
			fixed = cell(f.Fixed)
		}
		fmt.Fprintf(b, "| %s | %s | `%s` | %s | %s | %s |\n",
			cell(id), cell(f.Severity), cell(f.Pkg), cell(f.Version), fixed, cell(f.Where))
	}
}

// cellEscaper keeps a value inside its table cell: a pipe would end the
// cell, and a newline the row.
var cellEscaper = strings.NewReplacer("|", `\|`, "\n", " ")

func cell(s string) string {
	return cellEscaper.Replace(s)
}
