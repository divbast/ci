// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

// Package pnpmlock reads a pnpm lockfile, pnpm-lock.yaml, far enough to
// tell the packages a project runs with from those only its build uses.
//
// A lockfile is one YAML document, or two separated by "---", each in
// pnpm's v9 format (https://pnpm.io/lockfile-format). The first of two
// is pnpm's boot document: its config dependencies and the pnpm it runs
// as, under configDependencies and packageManagerDependencies. The last
// is the project's. In each, importers names every project's direct
// dependencies by group, and snapshots links each package to those it
// needs.
//
// A package is runtime when an importer's dependencies or
// optionalDependencies reach it, through the snapshots' dependencies and
// optionalDependencies, in any document. Every other package the
// lockfile names is build-only: only devDependencies reach it, or it is
// pnpm's own, from the boot document.
//
// The standard library reads no YAML. So the reader takes the two parts
// it needs, importers and snapshots, line by line in the block style pnpm
// writes, and refuses whatever it cannot follow there rather than guess:
// a runtime edge misread would make a runtime package build-only. Of the
// rest of a document it reads only lockfileVersion.
package pnpmlock

import (
	"errors"
	"fmt"
	"strings"
)

// Lockfile is every package a lockfile names, by name@version as its
// snapshots give them without their suffixes, and whether it is runtime.
type Lockfile struct{ kind map[string]bool }

// Runtime reports whether the package name at version can be part of
// what the project runs with: whether it is runtime, or one the lockfile
// does not name, which may be anything. Only a package the lockfile
// places outside every runtime graph is not.
func (l *Lockfile) Runtime(name, version string) bool {
	runtime, ok := l.kind[name+"@"+version]
	return runtime || !ok
}

// Read reads the lockfile data.
func Read(data []byte) (*Lockfile, error) {
	docs, err := documents(data)
	if err != nil {
		return nil, err
	}
	l := &Lockfile{kind: map[string]bool{}}
	for _, d := range docs {
		g, err := parse(d)
		if err != nil {
			return nil, err
		}
		if err := g.classify(l.kind); err != nil {
			return nil, err
		}
	}
	return l, nil
}

// line is one line of the file: its number, from 1, and its text without
// the line ending.
type line struct {
	n    int
	text string
}

// documents parts data into its YAML documents, dropping any that hold
// nothing.
func documents(data []byte) ([][]line, error) {
	var (
		docs [][]line
		cur  []line
	)
	keep := func() {
		for _, l := range cur {
			if t := strings.TrimSpace(l.text); t != "" && t[0] != '#' {
				docs = append(docs, cur)
				break
			}
		}
		cur = nil
	}
	n := 0
	for raw := range strings.Lines(string(data)) {
		n++
		text := strings.TrimSuffix(strings.TrimSuffix(raw, "\n"), "\r")
		switch {
		case text == "---":
			keep()
		case strings.HasPrefix(text, "--- ") || strings.HasPrefix(text, "---\t"):
			return nil, fmt.Errorf("line %d: a document marker, ---, with %q after it, which the reader does not follow", n, text[4:])
		default:
			cur = append(cur, line{n, text})
		}
	}
	keep()
	if len(docs) == 0 {
		return nil, errors.New("the file holds no lockfile document")
	}
	return docs, nil
}

// ref is a dependency, of an importer or of a snapshot: the name it is
// installed under, and the version or reference it resolved to.
type ref struct {
	n             int
	name, version string
}

// graph is what a document says of its packages: the importers'
// dependencies, runtime or not, and each snapshot's edges.
type graph struct {
	runtime, build []ref
	snaps          map[string][]ref
}

// What an importer's group or a snapshot's field holds, for the lines
// beneath it.
type holds int

const (
	nothing holds = iota // nothing, or nothing yet
	runtimeDeps
	buildDeps
	edges
	skipped // what the reader does not need
)

// parse reads one document.
func parse(lines []line) (*graph, error) {
	g := &graph{snaps: map[string][]ref{}}
	const (
		other = iota // a top-level key the reader skips, and all beneath it
		version
		importers
		snapshots
	)
	var (
		section  = other
		format   string
		importer string
		group    = nothing
		dep      *ref
		snap     string
		field    = nothing
		// pnpm writes importers in every document, one at least
		sawImporters bool
		nImporters   int
	)
	finish := func() error {
		if dep == nil {
			return nil
		}
		d := *dep
		dep = nil
		if d.version == "" {
			return fmt.Errorf("line %d: %s's dependency %s names no version", d.n, importer, d.name)
		}
		if group == runtimeDeps {
			g.runtime = append(g.runtime, d)
		} else {
			g.build = append(g.build, d)
		}
		return nil
	}

	for _, l := range lines {
		indent := len(l.text) - len(strings.TrimLeft(l.text, " "))
		rest := l.text[indent:]
		if strings.HasPrefix(rest, "\t") {
			return nil, fmt.Errorf("line %d: a tab indents it, which YAML forbids", l.n)
		}
		if strings.TrimSpace(rest) == "" || rest[0] == '#' {
			continue
		}
		if indent == 0 {
			if err := finish(); err != nil {
				return nil, err
			}
			e, err := entryOf(l.n, rest)
			if err != nil {
				return nil, err
			}
			switch e.key {
			case "lockfileVersion":
				section, format = version, e.value
			case "importers", "snapshots":
				if e.value != "" && e.value != "{}" {
					return nil, fmt.Errorf("line %d: %s is %q, where the reader follows only pnpm's block style", l.n, e.key, e.value)
				}
				section = importers
				if e.key == "snapshots" {
					section = snapshots
				} else {
					sawImporters = true
				}
			default:
				section = other
			}
			continue
		}

		var err error
		switch section {
		case other:
		case version:
			err = fmt.Errorf("line %d: something indented under lockfileVersion, which holds only a version", l.n)
		case importers:
			if indent == 2 {
				nImporters++
			}
			err = importerLine(l, indent, rest, &importer, &group, &dep, finish)
		case snapshots:
			err = snapshotLine(g, l, indent, rest, &snap, &field)
		}
		if err != nil {
			return nil, err
		}
	}
	if err := finish(); err != nil {
		return nil, err
	}
	switch {
	case format == "":
		return nil, errors.New("a document holds no lockfileVersion, so nothing says it is in pnpm's v9 format")
	case format != "9.0":
		return nil, fmt.Errorf("a document is in lockfileVersion %s, which the reader does not know: it reads pnpm's v9 format", format)
	case !sawImporters:
		return nil, errors.New("a document holds no importers, which pnpm writes in every one, so nothing says what its packages are reached from")
	case nImporters == 0 && len(g.snaps) > 0:
		return nil, errors.New("a document's importers are empty beside its snapshots, which pnpm never writes, so nothing says what reaches them")
	}
	return g, nil
}

// importerLine reads line l, indented by indent, in importers: an
// importer at 2, a group of its dependencies at 4, a dependency at 6, and
// its specifier and version at 8.
func importerLine(l line, indent int, rest string, importer *string, group *holds, dep **ref, finish func() error) error {
	if *group == skipped && indent > 4 {
		return nil
	}
	switch indent {
	case 2, 4, 6:
		if err := finish(); err != nil {
			return err
		}
	}
	e, err := entryOf(l.n, rest)
	if err != nil {
		return err
	}
	switch indent {
	case 2:
		if e.value != "" && e.value != "{}" {
			return fmt.Errorf("line %d: importer %s is %q, where the reader follows only pnpm's block style", l.n, e.key, e.value)
		}
		*importer, *group = e.key, nothing
	case 4:
		if *importer == "" {
			return fmt.Errorf("line %d: %s names no importer", l.n, e.key)
		}
		switch e.key {
		case "dependencies", "optionalDependencies":
			*group = runtimeDeps
		case "devDependencies", "configDependencies", "packageManagerDependencies":
			*group = buildDeps
		case "dependenciesMeta", "publishDirectory", "linkDirectory":
			*group = skipped
			return nil
		default:
			return fmt.Errorf("line %d: importer %s has %s, a group the reader does not know, so it cannot tell whether it is runtime", l.n, *importer, e.key)
		}
		switch e.value {
		case "":
		case "{}":
			*group = nothing
		default:
			return fmt.Errorf("line %d: %s's %s is in flow style, %q, which the reader does not follow", l.n, *importer, e.key, e.value)
		}
	case 6:
		if *group == nothing {
			return fmt.Errorf("line %d: dependency %s is under no group of dependencies", l.n, e.key)
		}
		if e.value != "" {
			return fmt.Errorf("line %d: dependency %s is %q on one line, where pnpm writes its specifier and version beneath it", l.n, e.key, e.value)
		}
		*dep = &ref{n: l.n, name: e.key}
	case 8:
		if *dep == nil {
			return fmt.Errorf("line %d: %s is under no dependency", l.n, e.key)
		}
		switch e.key {
		case "specifier":
		case "version":
			if e.value == "" || e.flow {
				return fmt.Errorf("line %d: %s's version is %q, which names no package", l.n, (*dep).name, e.value)
			}
			(*dep).version = e.value
		default:
			return fmt.Errorf("line %d: dependency %s has %s, a field the reader does not know", l.n, (*dep).name, e.key)
		}
	default:
		return fmt.Errorf("line %d is indented %d, which the importers' layout has no place for", l.n, indent)
	}
	return nil
}

// snapshotLine reads line l, indented by indent, in snapshots: a snapshot
// at 2, a field of it at 4, and a dependency's reference at 6.
func snapshotLine(g *graph, l line, indent int, rest string, snap *string, field *holds) error {
	if *field == skipped && indent > 4 {
		return nil
	}
	e, err := entryOf(l.n, rest)
	if err != nil {
		return err
	}
	switch indent {
	case 2:
		if e.value != "" && e.value != "{}" {
			return fmt.Errorf("line %d: snapshot %s is %q, where the reader follows only pnpm's block style", l.n, e.key, e.value)
		}
		if _, ok := g.snaps[e.key]; ok {
			return fmt.Errorf("line %d: snapshot %s is there twice", l.n, e.key)
		}
		g.snaps[e.key] = []ref{}
		*snap, *field = e.key, nothing
	case 4:
		if *snap == "" {
			return fmt.Errorf("line %d: %s is under no snapshot", l.n, e.key)
		}
		switch e.key {
		case "dependencies", "optionalDependencies":
			switch e.value {
			case "":
				*field = edges
			case "{}":
				*field = nothing
			default:
				return fmt.Errorf("line %d: snapshot %s's %s is in flow style, %q, which the reader does not follow", l.n, *snap, e.key, e.value)
			}
		case "transitivePeerDependencies", "optional", "id", "patched":
			*field = skipped
		default:
			return fmt.Errorf("line %d: snapshot %s has %s, a field the reader does not know, so it cannot tell whether it links packages", l.n, *snap, e.key)
		}
	case 6:
		if *field != edges {
			return fmt.Errorf("line %d: %s is under no snapshot's dependencies", l.n, e.key)
		}
		if e.value == "" || e.flow {
			return fmt.Errorf("line %d: snapshot %s's dependency %s is %q, which names no package", l.n, *snap, e.key, e.value)
		}
		g.snaps[*snap] = append(g.snaps[*snap], ref{n: l.n, name: e.key, version: e.value})
	default:
		return fmt.Errorf("line %d is indented %d, which the snapshots' layout has no place for", l.n, indent)
	}
	return nil
}

// classify adds every package of g to kind, as runtime when a runtime
// dependency reaches it, keeping runtime any that another document made
// so. Every reference must resolve to a snapshot, as pnpm writes them:
// one that does not is one the reader misread.
func (g *graph) classify(kind map[string]bool) error {
	resolve := func(r ref) (key string, ok bool, err error) {
		key, link := snapshotKey(r)
		if link {
			return "", false, nil
		}
		if _, ok := g.snaps[key]; !ok {
			return "", false, fmt.Errorf("line %d: %s resolves to %s, which no snapshot holds", r.n, r.name, key)
		}
		return key, true, nil
	}

	var queue []string
	for _, r := range g.runtime {
		key, ok, err := resolve(r)
		if err != nil {
			return err
		}
		if ok {
			queue = append(queue, key)
		}
	}
	for _, r := range g.build {
		if _, _, err := resolve(r); err != nil {
			return err
		}
	}
	for _, refs := range g.snaps {
		for _, r := range refs {
			if _, _, err := resolve(r); err != nil {
				return err
			}
		}
	}

	reached := map[string]bool{}
	for len(queue) > 0 {
		key := queue[0]
		queue = queue[1:]
		if reached[key] {
			continue
		}
		reached[key] = true
		for _, r := range g.snaps[key] {
			if next, ok, _ := resolve(r); ok {
				queue = append(queue, next)
			}
		}
	}
	for key := range g.snaps {
		pkg, err := packageKey(key)
		if err != nil {
			return err
		}
		kind[pkg] = kind[pkg] || reached[key]
	}
	return nil
}

// snapshotKey is the snapshot r's version names, as pnpm's lockfile
// format says: none for a link; the version itself for an alias, one that
// starts with @ or has an @ before any ( or :; and name@version for any
// other.
func snapshotKey(r ref) (key string, link bool) {
	v := r.version
	if strings.HasPrefix(v, "link:") {
		return "", true
	}
	head := v
	if i := strings.IndexAny(v, "(:"); i >= 0 {
		head = v[:i]
	}
	if strings.HasPrefix(v, "@") || strings.Contains(head, "@") {
		return v, false
	}
	return r.name + "@" + v, false
}

// packageKey is a snapshot's key without its trailing parenthesised
// groups, its patch hash and peer suffixes, which nest: name@version, as
// the packages a scanner lists are named.
func packageKey(key string) (string, error) {
	pkg := key
	for strings.HasSuffix(pkg, ")") {
		depth, i := 0, len(pkg)-1
		for ; i >= 0; i-- {
			switch pkg[i] {
			case ')':
				depth++
			case '(':
				depth--
			}
			if depth == 0 {
				break
			}
		}
		if i < 0 {
			return "", fmt.Errorf("snapshot %s has unbalanced parentheses", key)
		}
		pkg = pkg[:i]
	}
	if len(pkg) < 2 || !strings.Contains(pkg[1:], "@") {
		return "", fmt.Errorf("snapshot %s is no name@version", key)
	}
	return pkg, nil
}

// entry is a line's key, and its value: a scalar, unquoted, or a flow
// collection, kept as written, or "" for none.
type entry struct {
	key, value string
	flow       bool
}

// entryOf reads rest, line n without its indentation, as key: value.
func entryOf(n int, rest string) (entry, error) {
	if rest == "-" || strings.HasPrefix(rest, "- ") {
		return entry{}, fmt.Errorf("line %d: a list item, where the reader expects a key", n)
	}
	var key, after string
	if rest[0] == '\'' || rest[0] == '"' {
		k, tail, err := quoted(rest)
		if err != nil {
			return entry{}, fmt.Errorf("line %d: %w", n, err)
		}
		var ok bool
		if after, ok = strings.CutPrefix(tail, ":"); !ok {
			return entry{}, fmt.Errorf("line %d: no colon after the key %q", n, k)
		}
		key = k
	} else {
		var ok bool
		if key, after, ok = strings.Cut(rest, ": "); ok {
			after = " " + after
		} else if key, ok = strings.CutSuffix(rest, ":"); !ok {
			return entry{}, fmt.Errorf("line %d: %q is no key", n, rest)
		}
	}
	if after != "" && after[0] != ' ' {
		return entry{}, fmt.Errorf("line %d: %q after the key %q, with no space", n, after, key)
	}
	v := strings.TrimSpace(after)
	switch {
	case v == "":
		return entry{key: key}, nil
	case v[0] == '\'' || v[0] == '"':
		s, tail, err := quoted(v)
		if err != nil {
			return entry{}, fmt.Errorf("line %d: %w", n, err)
		}
		if tail != "" {
			return entry{}, fmt.Errorf("line %d: %q after the value of %s", n, tail, key)
		}
		return entry{key: key, value: s}, nil
	case v[0] == '{' || v[0] == '[':
		return entry{key: key, value: v, flow: true}, nil
	case strings.ContainsRune("&*!|>%@`", rune(v[0])) || strings.Contains(v, " #"):
		return entry{}, fmt.Errorf("line %d: %s's value %q is in a form of YAML the reader does not follow", n, key, v)
	}
	return entry{key: key, value: v}, nil
}

// quoted reads the quoted scalar s starts with, and returns it and what
// follows it.
func quoted(s string) (value, tail string, err error) {
	q := s[0]
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		c := s[i]
		switch {
		case q == '\'' && c == '\'':
			if i+1 < len(s) && s[i+1] == '\'' {
				b.WriteByte('\'')
				i++
				continue
			}
			return b.String(), s[i+1:], nil
		case q == '"' && c == '"':
			return b.String(), s[i+1:], nil
		case q == '"' && c == '\\':
			if i+1 == len(s) {
				return "", "", errors.New("an unterminated quote")
			}
			i++
			switch s[i] {
			case '\\', '"', '/':
				b.WriteByte(s[i])
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			default:
				return "", "", fmt.Errorf("the escape \\%c, which the reader does not follow", s[i])
			}
		default:
			b.WriteByte(c)
		}
	}
	return "", "", errors.New("an unterminated quote")
}
