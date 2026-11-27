// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Aryan Ameri <github@aryan.ameri.coffee>

package scan

import (
	"encoding/json"
	"errors"
	"fmt"
)

// ValidateSARIF makes the SARIF at path one code scanning accepts, or
// refuses it. Code scanning refuses a run with null or no array for its
// results or its tool.driver.rules, which grype writes for a lockfile it
// finds nothing in, and any scanner may, so ValidateSARIF rewrites the
// file with an empty array wherever either is null or missing. It returns
// an error, and leaves the file as it is, for a file that is not JSON; one
// with no runs array or no version string; one with a run that is not a
// JSON object, or lacks a tool, a tool.driver, or a non-empty
// tool.driver.name, or holds a results or rules that is neither null nor
// an array; or one with two runs of one tool, which code scanning refuses
// too.
func ValidateSARIF(path string) error {
	var doc map[string]any
	if err := readJSONFile(path, &doc); err != nil {
		return fmt.Errorf("cannot read %s as JSON: %w", path, err)
	}
	runs, ok := doc["runs"].([]any)
	if !ok {
		return fmt.Errorf("%s holds no runs array, so it is no SARIF", path)
	}
	seen := map[string]bool{}
	for i, r := range runs {
		run, ok := r.(map[string]any)
		if !ok {
			return fmt.Errorf("run %d of %s is not a JSON object, so it is no SARIF run", i, path)
		}
		if err := requireDriver(run); err != nil {
			return fmt.Errorf("run %d of %s: %w", i, path, err)
		}
		if err := requireArrays(run); err != nil {
			return fmt.Errorf("run %d of %s: %w", i, path, err)
		}
		tool := toolName(run)
		if seen[tool] {
			return fmt.Errorf("%s names runs of %s twice, and code scanning refuses two runs of one tool", path, tool)
		}
		seen[tool] = true
	}
	if v, ok := doc["version"].(string); !ok || v == "" {
		return fmt.Errorf("%s has no version string, so it is no SARIF", path)
	}
	data, err := json.MarshalIndent(doc, "", " ")
	if err != nil {
		return fmt.Errorf("rewrite %s: %w", path, err)
	}
	if err := writeFileIn(path, data); err != nil {
		return fmt.Errorf("rewrite %s: %w", path, err)
	}
	return nil
}

// requireArrays gives a SARIF run an array for its results and for its
// tool.driver.rules where it has none, or has null, and refuses one that
// is present but neither. Code scanning refuses a run with null in
// either. A nil slice marshals to null, so it counts as none.
func requireArrays(run map[string]any) error {
	if err := arrayAt(run, "results"); err != nil {
		return err
	}
	if d := driverOf(run); d != nil {
		return arrayAt(d, "rules")
	}
	return nil
}

// arrayAt makes m[key] an array: null or missing becomes an empty one,
// anything but an array is an error.
func arrayAt(m map[string]any, key string) error {
	switch v := m[key].(type) {
	case nil:
		m[key] = []any{}
	case []any:
		if v == nil {
			m[key] = []any{}
		}
	default:
		return fmt.Errorf("its %s is %T, not an array", key, v)
	}
	return nil
}

// requireDriver refuses a SARIF run with no tool, no tool.driver, or no
// non-empty string tool.driver.name.
func requireDriver(run map[string]any) error {
	tool, ok := run["tool"].(map[string]any)
	if !ok {
		return errors.New("has no tool object")
	}
	driver, ok := tool["driver"].(map[string]any)
	if !ok {
		return errors.New("has no tool.driver object")
	}
	if name, ok := driver["name"].(string); !ok || name == "" {
		return errors.New("has no tool.driver.name")
	}
	return nil
}
