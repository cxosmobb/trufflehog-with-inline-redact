package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/redaction"
)

type sourceScannerFunc func(context.Context, []byte) ([]byte, redaction.Report, error)

func (f sourceScannerFunc) Redact(ctx context.Context, input []byte) ([]byte, redaction.Report, error) {
	return f(ctx, input)
}

func replaceSyntheticSecret(_ context.Context, input []byte) ([]byte, redaction.Report, error) {
	return bytes.ReplaceAll(input, []byte("SYNTHETIC_SECRET"), []byte(redaction.Marker)), redaction.Report{}, nil
}

func writeSource(t *testing.T, dir, name, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertSource(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("unexpected content in %s", filepath.Base(path))
	}
}

func assertNoStagedFiles(t *testing.T, dir string) {
	t.Helper()
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.HasPrefix(entry.Name(), ".trufflehog-redact-") {
			t.Errorf("staged file was not removed: %s", filepath.Base(path))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func requireInPlaceSecurity(t *testing.T) {
	t.Helper()
	file, err := os.OpenFile(filepath.Join(t.TempDir(), "security-probe"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := captureSecurity(file); err != nil {
		if runtime.GOOS == "linux" || runtime.GOOS == "windows" || os.Getenv("REDACTION_REQUIRE_IN_PLACE") == "1" {
			t.Fatal("required in-place security metadata unavailable: " + err.Error())
		}
		t.Skip("complete in-place security metadata unavailable: " + err.Error())
	}
}

func TestSourceFilesCollectsSortedUniqueFilesAndSkipsGit(t *testing.T) {
	dir := t.TempDir()
	a := writeSource(t, dir, "a.go", "a", 0600)
	b := writeSource(t, dir, "b.go", "b", 0600)
	c := writeSource(t, dir, filepath.Join("nested", "c.go"), "c", 0600)
	writeSource(t, dir, filepath.Join(".git", "config"), "git metadata", 0600)
	got, err := sourceFiles([]string{dir, b, dir})
	if err != nil {
		for _, path := range []string{dir, b} {
			_, inspectionErr := filepath.EvalSymlinks(path)
			t.Logf("temporary fixture path %q: EvalSymlinks: %v", path, inspectionErr)
		}
		t.Fatal(err)
	}
	want := []string{a, b, c}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("collected %d files, expected exactly the three unique source files", len(got))
	}
}

func TestSourceFilesRejectsMissingOrEmptyInput(t *testing.T) {
	dir := t.TempDir()
	for _, inputs := range [][]string{nil, {dir}, {filepath.Join(dir, "missing")}} {
		if _, err := sourceFiles(inputs); err == nil {
			t.Error("accepted missing or empty source input")
		}
	}
}

func TestSourceFilesRejectsSymbolicLinks(t *testing.T) {
	dir := t.TempDir()
	target := writeSource(t, dir, "target.go", "source", 0600)
	link := filepath.Join(dir, "linked.go")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symbolic links are unavailable on this host")
	}
	if _, err := sourceFiles([]string{link}); err == nil {
		t.Error("accepted a symbolic source path")
	}
	if _, err := sourceFiles([]string{dir}); err == nil {
		t.Error("accepted a source tree containing a symbolic link")
	}
	linkedDir := filepath.Join(t.TempDir(), "linked-dir")
	if err := os.Symlink(dir, linkedDir); err != nil {
		t.Skip("directory symbolic links are unavailable on this host")
	}
	if _, err := sourceFiles([]string{filepath.Join(linkedDir, "target.go")}); err == nil {
		t.Error("accepted a source path with a symbolic ancestor")
	}
}

func TestSourceFilesRejectsCaseAliasSymlinkAncestor(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("case-sensitive path comparison is a Unix check")
	}
	dir := t.TempDir()
	targetDir := filepath.Join(dir, "UPPER")
	writeSource(t, targetDir, "source.go", "ordinary source", 0600)
	alias := filepath.Join(dir, "upper")
	if err := os.Symlink(targetDir, alias); err != nil {
		t.Skip("case-distinct symbolic links are unavailable on this filesystem")
	}
	if _, err := sourceFiles([]string{filepath.Join(alias, "source.go")}); err == nil {
		t.Error("accepted a symbolic ancestor whose target differs only in case")
	}
}

func TestRedactFilesOverwritesOriginalAndPreservesPermissions(t *testing.T) {
	requireInPlaceSecurity(t)
	dir := t.TempDir()
	path := writeSource(t, dir, "source.go", "prefix SYNTHETIC_SECRET suffix\n", 0640)
	unchanged := writeSource(t, dir, "unchanged.go", "ordinary source\n", 0600)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	unchangedBefore, err := os.Stat(unchanged)
	if err != nil {
		t.Fatal(err)
	}
	if err := redactFiles(context.Background(), sourceScannerFunc(replaceSyntheticSecret), []string{path, unchanged}, 1024, 2048); err != nil {
		t.Fatal(err)
	}
	assertSource(t, path, "prefix REDACTED suffix\n")
	assertSource(t, unchanged, "ordinary source\n")
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode().Perm() != before.Mode().Perm() {
		t.Error("source permissions changed during replacement")
	}
	unchangedAfter, err := os.Stat(unchanged)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(unchangedBefore, unchangedAfter) {
		t.Error("unchanged source was unnecessarily replaced")
	}
	assertNoStagedFiles(t, dir)
}

func TestRedactFilesFailureLeavesBatchUnchangedAndCleansStaging(t *testing.T) {
	requireInPlaceSecurity(t)
	for _, kind := range []string{"detector", "per-file limit", "total limit", "container"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			firstContent := "a SYNTHETIC_SECRET\n"
			secondContent := "longer SYNTHETIC_SECRET source\n"
			if kind == "container" {
				secondContent = "PK\x03\x04synthetic archive"
			}
			first := writeSource(t, dir, "first.go", firstContent, 0600)
			second := writeSource(t, dir, "second.go", secondContent, 0600)
			calls := 0
			scanner := sourceScannerFunc(func(ctx context.Context, input []byte) ([]byte, redaction.Report, error) {
				calls++
				if calls == 2 && kind == "detector" {
					staged, err := filepath.Glob(filepath.Join(dir, ".trufflehog-redact-*"))
					if err != nil || len(staged) != 1 {
						t.Error("first file was not staged before the second detector failure")
					}
					return nil, redaction.Report{}, errors.New("synthetic detector failure")
				}
				return replaceSyntheticSecret(ctx, input)
			})
			maxBytes, maxTotal := int64(1024), int64(2048)
			if kind == "per-file limit" {
				maxBytes = int64(len(firstContent))
			}
			if kind == "total limit" {
				maxTotal = int64(len(firstContent) + len(secondContent) - 1)
			}
			if err := redactFiles(context.Background(), scanner, []string{first, second}, maxBytes, maxTotal); err == nil {
				t.Fatal("accepted a batch whose second file failed")
			}
			assertSource(t, first, firstContent)
			assertSource(t, second, secondContent)
			assertNoStagedFiles(t, dir)
		})
	}
}

func TestRedactFilesDetectsChangedSourcesBeforeCommit(t *testing.T) {
	requireInPlaceSecurity(t)
	for _, firstContent := range []string{"SYNTHETIC_SECRET first\n", "ordinary first source\n"} {
		name := "staged"
		if !strings.Contains(firstContent, "SYNTHETIC_SECRET") {
			name = "unchanged"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			first := writeSource(t, dir, "first.go", firstContent, 0600)
			secondContent := "SYNTHETIC_SECRET second\n"
			second := writeSource(t, dir, "second.go", secondContent, 0600)
			calls := 0
			scanner := sourceScannerFunc(func(ctx context.Context, input []byte) ([]byte, redaction.Report, error) {
				calls++
				if calls == 2 {
					if err := os.WriteFile(first, []byte("external SYNTHETIC_SECRET change\n"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				return replaceSyntheticSecret(ctx, input)
			})
			if err := redactFiles(context.Background(), scanner, []string{first, second}, 1024, 2048); err == nil {
				t.Fatal("accepted a source that changed after it was scanned")
			}
			assertSource(t, first, "external SYNTHETIC_SECRET change\n")
			assertSource(t, second, secondContent)
			assertNoStagedFiles(t, dir)
		})
	}
}

func TestRedactFilesCancellationWithholdsCommit(t *testing.T) {
	requireInPlaceSecurity(t)
	for _, tc := range []struct{ name, content string }{
		{"staged", "SYNTHETIC_SECRET\n"},
		{"unchanged", "ordinary source\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := writeSource(t, dir, "source.go", tc.content, 0600)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			scanner := sourceScannerFunc(func(ctx context.Context, input []byte) ([]byte, redaction.Report, error) {
				cancel()
				return replaceSyntheticSecret(ctx, input)
			})
			if err := redactFiles(ctx, scanner, []string{path}, 1024, 2048); !errors.Is(err, context.Canceled) {
				t.Fatalf("expected cancellation, got %v", err)
			}
			assertSource(t, path, tc.content)
			assertNoStagedFiles(t, dir)
		})
	}
}

type failingSourceReader struct{}

func (failingSourceReader) Read([]byte) (int, error) {
	return 0, errors.New("synthetic reader error that must not be propagated")
}

func TestReadLimitedBoundariesAndErrors(t *testing.T) {
	for _, limit := range []int64{3, math.MaxInt64} {
		got, err := readLimited(strings.NewReader("abc"), limit)
		if err != nil || string(got) != "abc" {
			t.Errorf("size limit %d did not retain the complete input", limit)
		}
	}
	if got, err := readLimited(strings.NewReader("abcd"), 3); err == nil || got != nil {
		t.Error("oversized input was returned to the caller")
	}
	if got, err := readLimited(failingSourceReader{}, 10); err == nil || got != nil || strings.Contains(err.Error(), "must not be propagated") {
		t.Error("reader failure was not safely withheld")
	}
}

func TestUnsupportedContainers(t *testing.T) {
	tar := make([]byte, 512)
	copy(tar[257:], "ustar")
	for _, content := range [][]byte{
		[]byte("PK\x03\x04"), []byte("PK\x05\x06"), {0x1f, 0x8b},
		[]byte("7z\xbc\xaf\x27\x1c"), []byte("Rar!"), []byte("%PDF-1.7"), tar,
		[]byte("BZh"), {0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00},
		{0x28, 0xb5, 0x2f, 0xfd}, []byte("!<arch>\n"), {0xed, 0xab, 0xee, 0xdb},
	} {
		if !unsupportedContainer(content) {
			t.Error("accepted a recognized container")
		}
	}
	if unsupportedContainer([]byte("ordinary source text")) {
		t.Error("classified ordinary source as a container")
	}
}

func TestRunWithholdsStdoutOnInputErrors(t *testing.T) {
	for _, tc := range []struct {
		name  string
		args  []string
		input io.Reader
	}{
		{"size limit", []string{"--max-bytes=3"}, strings.NewReader("abcd")},
		{"container", nil, strings.NewReader("PK\x03\x04synthetic archive")},
		{"read failure", nil, failingSourceReader{}},
		{"invalid options", []string{"--max-total-bytes=0"}, strings.NewReader("ordinary source")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output, diagnostics bytes.Buffer
			if err := run(tc.args, tc.input, &output, &diagnostics); err == nil {
				t.Fatal("accepted invalid source input")
			}
			if output.Len() != 0 {
				t.Error("wrote source bytes to stdout despite an input error")
			}
		})
	}
}

func TestRunInPlaceRedactsActualSourceFile(t *testing.T) {
	requireInPlaceSecurity(t)
	dir := t.TempDir()
	path := writeSource(t, dir, "source.go", "const githubToken = \"ghp_abcdefghijklmnopqrstuvwxyz0123456789\"; // preserve\n", 0600)
	var output, diagnostics bytes.Buffer
	if err := run([]string{"--in-place", path}, strings.NewReader(""), &output, &diagnostics); err != nil {
		t.Fatal(err)
	}
	assertSource(t, path, "const githubToken = \"REDACTED\"; // preserve\n")
	if output.Len() != 0 {
		t.Error("in-place mode emitted source bytes on stdout")
	}
	assertNoStagedFiles(t, dir)
}

func TestRunStdinRedactsSourceAndIsIdempotent(t *testing.T) {
	input := "const githubToken = \"ghp_abcdefghijklmnopqrstuvwxyz0123456789\"; // preserve\n"
	want := "const githubToken = \"REDACTED\"; // preserve\n"
	for _, source := range []string{input, want} {
		var output, diagnostics bytes.Buffer
		if err := run(nil, strings.NewReader(source), &output, &diagnostics); err != nil {
			t.Fatal(err)
		}
		if output.String() != want {
			t.Fatal("stdin source was not exactly redacted or was changed on a second scan")
		}
		if diagnostics.Len() != 0 {
			t.Fatal("successful source redaction emitted diagnostics")
		}
	}
}

func TestSourceFilesEnforcesEnumerationBudgetAndCancellation(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a", "b", "c"} {
		writeSource(t, dir, name, "", 0600)
	}
	if _, err := sourceFilesLimited(context.Background(), []string{dir}, 2); err == nil {
		t.Fatal("accepted too many empty files despite the enumeration budget")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := sourceFilesLimited(ctx, []string{dir}, 10); !errors.Is(err, context.Canceled) {
		t.Fatalf("enumeration ignored cancellation: %v", err)
	}
}

func TestSourceFilesEnforcesDirectoryBudget(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a", "b", "c"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := sourceFilesLimited(context.Background(), []string{dir}, 2); err == nil || !strings.Contains(err.Error(), "directory count") {
		t.Fatal("an empty directory tree bypassed the enumeration budget")
	}
}

func TestSourceFilesDeduplicatesCaseAliasesOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("case aliases are a Windows check")
	}
	path := writeSource(t, t.TempDir(), "mixedCase.go", "ordinary", 0600)
	got, err := sourceFiles([]string{path, strings.ToUpper(path)})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatal("Windows aliases were treated as separate source files")
	}
}

func TestRedactFilesWithholdsTamperedStaging(t *testing.T) {
	requireInPlaceSecurity(t)
	dir := t.TempDir()
	first := writeSource(t, dir, "first.go", "SYNTHETIC_SECRET first", 0644)
	second := writeSource(t, dir, "second.go", "SYNTHETIC_SECRET second", 0600)
	calls := 0
	scanner := sourceScannerFunc(func(ctx context.Context, input []byte) ([]byte, redaction.Report, error) {
		calls++
		if calls == 2 {
			staged, err := filepath.Glob(filepath.Join(dir, ".trufflehog-redact-*"))
			if err != nil || len(staged) != 1 {
				t.Fatal("missing staged source")
			}
			info, err := os.Stat(staged[0])
			if err != nil {
				t.Fatal(err)
			}
			if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
				t.Error("staged source was exposed before commit")
			}
			if err := os.WriteFile(staged[0], []byte("SYNTHETIC_SECRET attacker change"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		return replaceSyntheticSecret(ctx, input)
	})
	if err := redactFiles(context.Background(), scanner, []string{first, second}, 1024, 2048); err == nil {
		t.Fatal("committed an unscanned staged source")
	}
	assertSource(t, first, "SYNTHETIC_SECRET first")
	assertSource(t, second, "SYNTHETIC_SECRET second")
	assertNoStagedFiles(t, dir)
}

func TestRedactFilesRejectsIdentitySubstitutionWithIdenticalBytes(t *testing.T) {
	requireInPlaceSecurity(t)
	dir := t.TempDir()
	first := writeSource(t, dir, "first.go", "SYNTHETIC_SECRET first", 0600)
	second := writeSource(t, dir, "second.go", "SYNTHETIC_SECRET second", 0600)
	calls := 0
	scanner := sourceScannerFunc(func(ctx context.Context, input []byte) ([]byte, redaction.Report, error) {
		calls++
		if calls == 2 {
			replacement := writeSource(t, dir, "replacement.go", "SYNTHETIC_SECRET first", 0600)
			if err := os.Rename(replacement, first); err != nil {
				t.Fatal(err)
			}
		}
		return replaceSyntheticSecret(ctx, input)
	})
	if err := redactFiles(context.Background(), scanner, []string{first, second}, 1024, 2048); err == nil {
		t.Fatal("committed over an externally substituted source inode")
	}
	assertSource(t, first, "SYNTHETIC_SECRET first")
	assertSource(t, second, "SYNTHETIC_SECRET second")
	assertNoStagedFiles(t, dir)
}

func TestRedactFilesRejectsPermissionChanges(t *testing.T) {
	requireInPlaceSecurity(t)
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission change check")
	}
	dir := t.TempDir()
	first := writeSource(t, dir, "first.go", "SYNTHETIC_SECRET first", 0600)
	second := writeSource(t, dir, "second.go", "SYNTHETIC_SECRET second", 0600)
	calls := 0
	scanner := sourceScannerFunc(func(ctx context.Context, input []byte) ([]byte, redaction.Report, error) {
		calls++
		if calls == 2 {
			if err := os.Chmod(first, 0644); err != nil {
				t.Fatal(err)
			}
		}
		return replaceSyntheticSecret(ctx, input)
	})
	if err := redactFiles(context.Background(), scanner, []string{first, second}, 1024, 2048); err == nil {
		t.Fatal("silently overwrote an external permission change")
	}
	assertSource(t, first, "SYNTHETIC_SECRET first")
	assertNoStagedFiles(t, dir)
}

func TestRedactFilesRejectsParentDirectoryReplacement(t *testing.T) {
	requireInPlaceSecurity(t)
	parent := t.TempDir()
	dir := filepath.Join(parent, "import")
	first := writeSource(t, dir, "first.go", "SYNTHETIC_SECRET first", 0600)
	second := writeSource(t, dir, "second.go", "SYNTHETIC_SECRET second", 0600)
	moved := filepath.Join(parent, "moved")
	calls := 0
	scanner := sourceScannerFunc(func(ctx context.Context, input []byte) ([]byte, redaction.Report, error) {
		calls++
		if calls == 1 {
			if err := os.Rename(dir, moved); err != nil {
				t.Skip("directory renames with an open directory handle are unavailable")
			}
			writeSource(t, dir, "first.go", "SYNTHETIC_SECRET first", 0600)
			writeSource(t, dir, "second.go", "SYNTHETIC_SECRET second", 0600)
		}
		return replaceSyntheticSecret(ctx, input)
	})
	if err := redactFiles(context.Background(), scanner, []string{first, second}, 1024, 2048); err == nil {
		t.Fatal("redirected source writes to a substituted input directory")
	}
	assertSource(t, first, "SYNTHETIC_SECRET first")
	assertSource(t, second, "SYNTHETIC_SECRET second")
	assertSource(t, filepath.Join(moved, "first.go"), "SYNTHETIC_SECRET first")
	assertNoStagedFiles(t, parent)
}

func TestRedactFilesRejectsNewSymlinkWithIdenticalBytes(t *testing.T) {
	requireInPlaceSecurity(t)
	dir := t.TempDir()
	first := writeSource(t, dir, "first.go", "SYNTHETIC_SECRET first", 0600)
	second := writeSource(t, dir, "second.go", "SYNTHETIC_SECRET second", 0600)
	external := writeSource(t, t.TempDir(), "external.go", "SYNTHETIC_SECRET first", 0600)
	probe := filepath.Join(dir, "probe-link")
	if err := os.Symlink(external, probe); err != nil {
		t.Skip("symbolic links are unavailable on this host")
	}
	if err := os.Remove(probe); err != nil {
		t.Fatal(err)
	}
	calls := 0
	scanner := sourceScannerFunc(func(ctx context.Context, input []byte) ([]byte, redaction.Report, error) {
		calls++
		if calls == 2 {
			if err := os.Remove(first); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(external, first); err != nil {
				t.Fatal(err)
			}
		}
		return replaceSyntheticSecret(ctx, input)
	})
	if err := redactFiles(context.Background(), scanner, []string{first, second}, 1024, 2048); err == nil {
		t.Fatal("accepted a source symlink added after enumeration")
	}
	assertSource(t, external, "SYNTHETIC_SECRET first")
	assertSource(t, second, "SYNTHETIC_SECRET second")
	assertNoStagedFiles(t, dir)
}

func TestRunSanitizesRejectedOptions(t *testing.T) {
	secret := "SYNTHETIC_SECRET"
	for _, args := range [][]string{{"--timeout=" + secret}, {"--" + secret}, {"--max-files=" + secret}} {
		var output, diagnostics bytes.Buffer
		err := run(args, strings.NewReader("ordinary source"), &output, &diagnostics)
		if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(diagnostics.String(), secret) || output.Len() != 0 {
			t.Error("rejected command options disclosed their secret-bearing values")
		}
	}
	var help, output bytes.Buffer
	if err := run([]string{"--help"}, strings.NewReader(""), &output, &help); err != nil || !strings.Contains(help.String(), "--in-place") && !strings.Contains(help.String(), "-in-place") {
		t.Error("sanitization suppressed explicit help")
	}
}

type unsafeOutputWriter struct{ short bool }

func (w unsafeOutputWriter) Write(data []byte) (int, error) {
	if w.short {
		return len(data) - 1, nil
	}
	return 0, errors.New("SYNTHETIC_SECRET writer diagnostic")
}

func TestRunSanitizesOutputErrorsAndRejectsShortWrites(t *testing.T) {
	for _, writer := range []unsafeOutputWriter{{}, {short: true}} {
		var diagnostics bytes.Buffer
		err := run(nil, strings.NewReader("ordinary source"), writer, &diagnostics)
		if err == nil || strings.Contains(err.Error(), "SYNTHETIC_SECRET") {
			t.Error("output failure was accepted or leaked an unsafe writer diagnostic")
		}
	}
}
