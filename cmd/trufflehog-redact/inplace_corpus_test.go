package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/internal/redactiontest"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
	"github.com/trufflesecurity/trufflehog/v3/pkg/redaction"
)

// Each actual detector first proves it detects a positive offline sample. The
// disk workflow must then produce exactly the same validated source edits;
// separate exact fixtures independently specify sensitive/public byte ranges.
func TestEveryDetectorRedactsInPlace(t *testing.T) {
	if testing.Short() {
		if os.Getenv("REDACTION_REQUIRE_IN_PLACE") == "1" {
			t.Fatal("required all-detector in-place coverage cannot use short mode")
		}
		t.Skip("all-detector in-place corpus is disabled in short mode")
	}
	requireInPlaceSecurity(t)
	fixtures := redactiontest.Fixtures(t)
	covered := 0
	for _, fixture := range fixtures {
		if t.Run(fixture.Name, func(t *testing.T) {
			dir := t.TempDir()
			path := writeSource(t, dir, "original.txt", string(fixture.Input), 0640)
			before, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			scanner, err := redaction.New([]detectors.Detector{fixture.Detector})
			if err != nil {
				t.Fatal("cannot construct fixture scanner")
			}
			var previous os.FileInfo
			for pass := 1; pass <= 2; pass++ {
				if err := redactFiles(context.Background(), scanner, []string{path}, 16<<20, 256<<20); err != nil {
					t.Fatalf("in-place pass %d failed: %v", pass, err)
				}
				got, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(got, fixture.Expected) {
					t.Fatalf("in-place pass %d differs from validated source edits", pass)
				}
				info, err := os.Stat(path)
				if err != nil || info.Mode().Perm() != before.Mode().Perm() {
					t.Fatal("source permissions changed")
				}
				if previous != nil && !os.SameFile(previous, info) {
					t.Fatal("second pass unnecessarily replaced the redacted file")
				}
				previous = info
				assertNoStagedFiles(t, dir)
			}
		}) {
			covered++
		}
	}
	t.Logf("actual in-place detector coverage: %d/%d scanner instances; 2 passes each", covered, len(fixtures))
}

// A real command subprocess applies the complete production registry to every
// fixture in a nested source tree. Comparing against the full-registry library
// result isolates flag/discovery/transaction regressions from additional valid
// findings produced by overlapping detectors.
func TestCommandRedactsDetectorCorpusInPlace(t *testing.T) {
	if testing.Short() {
		if os.Getenv("REDACTION_REQUIRE_IN_PLACE") == "1" {
			t.Fatal("required all-detector in-place coverage cannot use short mode")
		}
		t.Skip("all-detector command corpus is disabled in short mode")
	}
	requireInPlaceSecurity(t)
	fixtures := redactiontest.Fixtures(t)
	scanner, err := redaction.New(defaults.RedactionDetectors())
	if err != nil {
		t.Fatal("cannot construct production scanner registry")
	}
	dir := t.TempDir()
	expected := make(map[string][]byte, len(fixtures)+1)
	modes := make(map[string]os.FileMode, len(fixtures)+1)
	additionalFindings := 0
	for i, fixture := range fixtures {
		output, report, err := scanner.Redact(context.Background(), fixture.Input)
		if err != nil {
			t.Errorf("%s: production registry cannot redact fixture: %v", fixture.Name, err)
			continue
		}
		if report.Replacements == 0 || bytes.Equal(output, fixture.Input) {
			t.Errorf("%s: production registry did not replace the detected secret", fixture.Name)
			continue
		}
		if !bytes.Equal(output, fixture.Expected) {
			additionalFindings++
		}
		name := filepath.Join(fmt.Sprintf("group-%02d", i/64), fmt.Sprintf("%03d-%s.txt", i, fixture.Name))
		path := writeSource(t, dir, name, string(fixture.Input), 0640)
		expected[path] = output
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		modes[path] = info.Mode().Perm()
	}
	if t.Failed() {
		t.Fatal("production registry fixture preparation failed; no batch was forwarded")
	}
	clean := writeSource(t, dir, "unchanged.txt", "ordinary source; preserve every byte\r\n", 0640)
	expected[clean] = []byte("ordinary source; preserve every byte\r\n")
	previous := make(map[string]os.FileInfo, len(expected))
	previous[clean], err = os.Stat(clean)
	if err != nil {
		t.Fatal(err)
	}
	modes[clean] = previous[clean].Mode().Perm()
	for pass := 1; pass <= 2; pass++ {
		runRedactCommand(t, "--in-place", "--timeout=9m", dir)
		for path, want := range expected {
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("%s: command output differs from validated edits on pass %d", filepath.Base(path), pass)
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != modes[path] {
				t.Fatalf("%s: command changed source permissions", filepath.Base(path))
			}
			if original := previous[path]; original != nil && !os.SameFile(original, info) {
				t.Fatalf("%s: unchanged file replaced on pass %d", filepath.Base(path), pass)
			}
			previous[path] = info
		}
		assertNoStagedFiles(t, dir)
	}
	t.Logf("production command in-place coverage: %d/%d scanner fixtures, %d files, 2 passes; %d fixtures also matched additional detectors", len(fixtures), len(fixtures), len(expected), additionalFindings)
}
