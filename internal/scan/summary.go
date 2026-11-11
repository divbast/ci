// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package scan

import (
	"fmt"
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
// them, then how many it has, and each of those.
func Listing(against, verdict string, s Split) string {
	var b strings.Builder
	fmt.Fprintf(&b, "compared with %s\n", against)
	fmt.Fprintf(&b, "%d %s:\n", len(s.New), verdict)
	for _, f := range s.New {
		fmt.Fprintf(&b, "  %s\n", f)
	}
	fmt.Fprintf(&b, "%d already published, so advisory:\n", len(s.Old))
	for _, f := range s.Old {
		fmt.Fprintf(&b, "  %s\n", f)
	}
	return b.String()
}

// Summary returns the Markdown the scan appends to the run's summary page
// for arch: what it compared with, warning as a callout unless it is
// empty, then a table of the findings the published image lacks, under
// heading, and one of those it has.
func Summary(arch, against, heading, warning string, s Split) string {
	var b strings.Builder
	fmt.Fprintf(&b, "### Vulnerability scan, %s\n\n", arch)
	fmt.Fprintf(&b, "Compared with `%s`.\n\n", against)
	if warning != "" {
		fmt.Fprintf(&b, "> **Warning:** %s\n\n", warning)
	}
	fmt.Fprintf(&b, "**%s: %d**\n\n", heading, len(s.New))
	table(&b, s.New)
	fmt.Fprintf(&b, "\n**Already published, so advisory: %d**\n\n", len(s.Old))
	table(&b, s.Old)
	b.WriteString("\n")
	return b.String()
}

func table(b *strings.Builder, findings []Finding) {
	if len(findings) == 0 {
		b.WriteString("None.\n")
		return
	}
	b.WriteString("| Vulnerability | Severity | Package | Installed | Fixed in | Where |\n")
	b.WriteString("|---|---|---|---|---|---|\n")
	for _, f := range findings {
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
