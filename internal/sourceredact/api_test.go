package sourceredact

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/redaction"
)

func TestRedactInPlaceHonorsFileSelection(t *testing.T) {
	requireInPlaceSecurity(t)
	dir := t.TempDir()
	selected := writeSource(t, dir, "included/source.go", "SYNTHETIC_SECRET keep", 0600)
	excluded := writeSource(t, dir, "excluded/source.go", "SYNTHETIC_SECRET unchanged", 0600)
	options := Defaults()
	var visited []string
	options.IncludePath = func(path string) bool {
		if !filepath.IsAbs(path) {
			t.Fatal("source selector received a relative path")
		}
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			t.Fatal("source selector received a directory or invalid file")
		}
		visited = append(visited, path)
		return path == selected
	}
	if err := RedactInPlace(context.Background(), sourceScannerFunc(replaceSyntheticSecret), []string{dir}, options); err != nil {
		t.Fatal(err)
	}
	if len(visited) != 2 {
		t.Fatal("source selector did not inspect both regular files")
	}
	assertSource(t, selected, "REDACTED keep")
	assertSource(t, excluded, "SYNTHETIC_SECRET unchanged")
	assertNoStagedFiles(t, dir)
}

func TestRedactInPlacePrunesExcludedDirectories(t *testing.T) {
	requireInPlaceSecurity(t)
	dir := t.TempDir()
	selected := writeSource(t, dir, "included/source.go", "SYNTHETIC_SECRET keep", 0600)
	excluded := writeSource(t, dir, "excluded/nested/source.go", "SYNTHETIC_SECRET unchanged", 0600)
	options := Defaults()
	options.SkipDirectory = func(path string) bool {
		return filepath.Base(path) == "excluded"
	}
	options.IncludePath = func(path string) bool {
		if strings.Contains(path, string(filepath.Separator)+"excluded"+string(filepath.Separator)) {
			t.Fatal("enumeration descended into an excluded directory")
		}
		return true
	}
	if err := RedactInPlace(context.Background(), sourceScannerFunc(replaceSyntheticSecret), []string{dir}, options); err != nil {
		t.Fatal(err)
	}
	assertSource(t, selected, "REDACTED keep")
	assertSource(t, excluded, "SYNTHETIC_SECRET unchanged")
	assertNoStagedFiles(t, dir)
}

func TestRedactInPlaceRejectsInvalidOptionsBeforeScanning(t *testing.T) {
	scanner := sourceScannerFunc(func(context.Context, []byte) ([]byte, redaction.Report, error) {
		t.Fatal("invalid request reached the scanner")
		return nil, redaction.Report{}, nil
	})
	for _, options := range []Options{{}, {MaxBytes: -1, MaxTotalBytes: 1, MaxFiles: 1}, {MaxBytes: 1, MaxTotalBytes: -1, MaxFiles: 1}, {MaxBytes: 1, MaxTotalBytes: 1, MaxFiles: -1}} {
		if err := RedactInPlace(context.Background(), scanner, nil, options); err == nil {
			t.Fatal("accepted invalid source limits")
		}
	}
	if err := RedactInPlace(context.Background(), nil, nil, Defaults()); err == nil {
		t.Fatal("accepted a missing scanner")
	}
}

func TestMainCommandArgsPreservesNativeSourceCommand(t *testing.T) {
	got := mainCommandArgs([]string{"--in-place", "--timeout=9m", "--max-bytes", "1024", "--max-total-bytes=2048", "--max-files=5", "source"})
	want := []string{"--no-update", "--no-verification", "--log-level=-1", "--json", "filesystem", "--in-place", "--redaction-timeout=9m", "--redaction-max-bytes", "1024", "--redaction-max-total-bytes=2048", "--redaction-max-files=5", "source"}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("native production test arguments differ from the source command interface")
	}
}

func TestRedactInPlaceCallbackSeesOnlyValidatedOriginals(t *testing.T) {
	requireInPlaceSecurity(t)
	dir := t.TempDir()
	first := writeSource(t, dir, "first.go", "SYNTHETIC_SECRET first", 0600)
	second := writeSource(t, dir, "second.go", "SYNTHETIC_SECRET second", 0600)
	planned, callbacks := 0, 0
	scanner := sourceScannerFunc(func(ctx context.Context, data []byte) ([]byte, redaction.Report, error) {
		planned++
		return replaceSyntheticSecret(ctx, data)
	})
	options := Defaults()
	options.BeforeCommit = func(ctx context.Context) error {
		callbacks++
		if planned != 2 || ctx.Err() != nil {
			t.Fatal("callback ran before the complete batch was planned")
		}
		assertSource(t, first, "SYNTHETIC_SECRET first")
		assertSource(t, second, "SYNTHETIC_SECRET second")
		assertNoStagedFiles(t, dir)
		return nil
	}
	if err := RedactInPlace(context.Background(), scanner, []string{dir}, options); err != nil {
		t.Fatal(err)
	}
	if callbacks != 1 {
		t.Fatal("native scan callback did not run exactly once")
	}
	assertSource(t, first, "REDACTED first")
	assertSource(t, second, "REDACTED second")
	assertNoStagedFiles(t, dir)
}

func TestRedactInPlaceCallbackFailuresWithholdBatch(t *testing.T) {
	requireInPlaceSecurity(t)
	for _, mode := range []string{"error", "source-change", "cancellation"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			first := writeSource(t, dir, "first.go", "SYNTHETIC_SECRET first", 0600)
			second := writeSource(t, dir, "second.go", "SYNTHETIC_SECRET second", 0600)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cause := errors.New("synthetic ordinary scan failure")
			options := Defaults()
			options.BeforeCommit = func(context.Context) error {
				assertNoStagedFiles(t, dir)
				switch mode {
				case "error":
					return cause
				case "source-change":
					return os.WriteFile(second, []byte("SYNTHETIC_SECRET modified"), 0600)
				case "cancellation":
					cancel()
				}
				return nil
			}
			err := RedactInPlace(ctx, sourceScannerFunc(replaceSyntheticSecret), []string{dir}, options)
			if err == nil {
				t.Fatal("callback failure or mutation did not withhold the complete batch")
			}
			if mode == "error" && !errors.Is(err, cause) {
				t.Fatal("callback error was not returned to the caller")
			}
			if mode == "cancellation" && !errors.Is(err, context.Canceled) {
				t.Fatal("callback cancellation was not preserved")
			}
			assertSource(t, first, "SYNTHETIC_SECRET first")
			wantSecond := "SYNTHETIC_SECRET second"
			if mode == "source-change" {
				wantSecond = "SYNTHETIC_SECRET modified"
			}
			assertSource(t, second, wantSecond)
			assertNoStagedFiles(t, dir)
		})
	}
}
