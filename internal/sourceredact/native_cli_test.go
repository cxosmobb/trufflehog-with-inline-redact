package sourceredact

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Synthetic: ghp_ + first36hex(SHA256("trufflehog-native-inline-redaction-synthetic-fixture")).
const nativeTestSecret = "ghp_732e944dd9bca8079d5304a4d30f05e15e24"
const nativeTestSource = "const token = '" + nativeTestSecret + "'; // preserve source\r\n"

func nativeBinary(t *testing.T) string {
	t.Helper()
	binary := os.Getenv("REDACTION_TEST_MAIN_BINARY")
	if binary == "" {
		if os.Getenv("REDACTION_REQUIRE_IN_PLACE") == "1" {
			t.Fatal("required full TruffleHog executable coverage needs REDACTION_TEST_MAIN_BINARY")
		}
		t.Skip("full TruffleHog executable was not supplied")
	}
	return binary
}

type nativeResult struct {
	code           int
	stdout, stderr []byte
}

func nativeCommand(t *testing.T, args ...string) nativeResult {
	t.Helper()
	return nativeCommandAt(t, "", args...)
}

func nativeCommandAt(t *testing.T, dir string, args ...string) nativeResult {
	t.Helper()
	binary := nativeBinary(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, append([]string{"--no-update", "--no-verification", "--log-level=-1", "--json"}, args...)...)
	command.Dir = dir
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	if ctx.Err() != nil {
		t.Fatal("full TruffleHog command exceeded the offline test deadline")
	}
	result := nativeResult{stdout: stdout.Bytes(), stderr: stderr.Bytes()}
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatalf("cannot start full TruffleHog command: %T", err)
		}
		result.code = exit.ExitCode()
	}
	return result
}

func assertNativeStatus(t *testing.T, result nativeResult, want int, secretFree bool) {
	t.Helper()
	if result.code != want {
		t.Fatalf("full TruffleHog exit code %d, want %d (stdout=%d bytes; stderr=%d bytes)", result.code, want, len(result.stdout), len(result.stderr))
	}
	if secretFree && (bytes.Contains(result.stdout, []byte(nativeTestSecret)) || bytes.Contains(result.stderr, []byte(nativeTestSecret))) {
		t.Fatal("full TruffleHog exposed source credentials in command output")
	}
}

func assertNativeFindings(t *testing.T, result nativeResult, want int) {
	t.Helper()
	assertNativeStatus(t, result, want, false)
	if len(result.stderr) != 0 {
		t.Fatalf("native source redaction emitted diagnostics (%d bytes)", len(result.stderr))
	}
	assertNativeJSONOutput(t, result.stdout)
}

func assertNativeJSONOutput(t *testing.T, data []byte) {
	t.Helper()
	if bytes.Contains(data, []byte(".trufflehog-redact-")) {
		t.Fatal("ordinary findings included a private staging filename")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	for {
		var finding map[string]json.RawMessage
		err := decoder.Decode(&finding)
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil || finding["DetectorName"] == nil {
			t.Fatal("native source redaction did not retain normal JSON findings")
		}
	}
}

func nativeRepositoryRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal("cannot locate native CLI source")
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "main.go")); err == nil {
			if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("cannot locate native CLI repository")
		}
		dir = parent
	}
}

func TestNativeCLIKeepsCommandsAndFlags(t *testing.T) {
	nativeBinary(t)
	rootHelp := nativeCommand(t, "--help")
	assertNativeStatus(t, rootHelp, 0, true)
	help := strings.ReplaceAll(string(append(append([]byte{}, rootHelp.stdout...), rootHelp.stderr...)), "--[no-]", "--")
	for _, flag := range []string{"--json", "--no-verification", "--include-detectors", "--exclude-detectors", "--fail", "--in-place", "--redaction-timeout"} {
		if !strings.Contains(help, flag) {
			t.Fatalf("full TruffleHog help omitted %s", flag)
		}
	}
	file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(nativeRepositoryRoot(t), "main.go"), nil, 0)
	if err != nil {
		t.Fatal("cannot inspect native command declarations")
	}
	var names []string
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		fn, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || fn.Sel.Name != "Command" {
			return true
		}
		receiver, ok := fn.X.(*ast.Ident)
		if !ok || receiver.Name != "cli" {
			return true
		}
		literal, ok := call.Args[0].(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			t.Fatal("native command name is no longer a static string")
		}
		name, err := strconv.Unquote(literal.Value)
		if err != nil {
			t.Fatal("invalid native command declaration")
		}
		names = append(names, name)
		return true
	})
	if len(names) < 10 {
		t.Fatal("native command preservation check did not inspect the full CLI")
	}
	names = append(names, "analyze") // Registered by analyzer.Command rather than cli.Command.
	sort.Strings(names)
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			result := nativeCommand(t, name, "--help")
			assertNativeStatus(t, result, 0, true)
			if len(result.stdout)+len(result.stderr) == 0 {
				t.Fatal("native subcommand help was empty")
			}
		})
	}
	t.Logf("full TruffleHog preserves %d offline command help routes and native/global redaction flags", len(names))
}

func assertNativeJSONSecret(t *testing.T, result nativeResult) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(result.stdout))
	found := false
	for {
		var finding struct {
			Raw, DetectorName string
			Verified          bool
		}
		err := decoder.Decode(&finding)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal("ordinary native scan did not retain JSON findings")
		}
		if finding.Raw == nativeTestSecret && finding.DetectorName == "Github" && !finding.Verified {
			found = true
		}
	}
	if !found {
		t.Fatal("ordinary native JSON output omitted the original detected credential")
	}
}

func TestNativeOrdinaryScansKeepJSONAndFailBehavior(t *testing.T) {
	nativeBinary(t)
	dir := t.TempDir()
	path := writeSource(t, dir, "original.go", nativeTestSource, 0600)
	for _, useFile := range []bool{false, true} {
		t.Run(map[bool]string{false: "arguments", true: "argument-file"}[useFile], func(t *testing.T) {
			args := []string{"--json", "--include-detectors=Github", "filesystem", path}
			if useFile {
				arguments := writeSource(t, t.TempDir(), "arguments.txt", strings.Join(args, "\n")+"\n", 0600)
				args = []string{"@" + arguments}
			}
			result := nativeCommand(t, args...)
			assertNativeStatus(t, result, 0, false)
			assertNativeJSONSecret(t, result)
			assertSource(t, path, nativeTestSource)
		})
	}
	result := nativeCommand(t, "--json", "--fail", "--include-detectors=Github", "filesystem", path)
	assertNativeStatus(t, result, 183, false)
	assertNativeJSONSecret(t, result)
	assertSource(t, path, nativeTestSource)
	assertNoStagedFiles(t, dir)
}

func TestNativeInPlaceFailAndOutputFilters(t *testing.T) {
	nativeBinary(t)
	requireInPlaceSecurity(t)
	for _, test := range []struct {
		name  string
		flags []string
		code  int
	}{
		{"fail", []string{"--fail"}, 183},
		{"output-filters", []string{"--json", "--results=verified", "--only-verified", "--filter-entropy=100"}, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			path := writeSource(t, dir, "original.go", nativeTestSource, 0600)
			args := append(append([]string{}, test.flags...), "--include-detectors=Github", "filesystem", "--in-place", path)
			result := nativeCommand(t, args...)
			assertNativeFindings(t, result, test.code)
			if test.name == "fail" {
				assertNativeJSONSecret(t, result)
			} else if len(result.stdout) != 0 {
				t.Fatal("verified-only output included an unverified candidate")
			}
			assertSource(t, path, strings.ReplaceAll(nativeTestSource, nativeTestSecret, "REDACTED"))
			assertNativeFindings(t, nativeCommand(t, args...), 0)
			assertNoStagedFiles(t, dir)
		})
	}
}

func TestNativeInPlaceKeepsPathSelectionAndDirectoryFlag(t *testing.T) {
	nativeBinary(t)
	requireInPlaceSecurity(t)
	dir := t.TempDir()
	selected := writeSource(t, dir, "included/first.go", nativeTestSource, 0600)
	fileExcluded := writeSource(t, dir, "included/excluded.go", nativeTestSource, 0600)
	dirExcluded := writeSource(t, dir, "excluded/nested/first.go", nativeTestSource, 0600)
	notIncluded := writeSource(t, dir, "included/other.go", nativeTestSource, 0600)
	git := writeSource(t, dir, ".git/config", nativeTestSource, 0600)
	controls := t.TempDir()
	include := writeSource(t, controls, "include.txt", "(first|excluded)\\.go$\n", 0600)
	exclude := writeSource(t, controls, "exclude.txt", "excluded\\.go$\nexcluded$\n", 0600)
	result := nativeCommand(t, "--include-detectors=Github", "filesystem", "--in-place", "--include-paths", include, "--exclude-paths", exclude, "--directory", dir)
	assertNativeFindings(t, result, 0)
	assertSource(t, selected, strings.ReplaceAll(nativeTestSource, nativeTestSecret, "REDACTED"))
	for _, path := range []string{fileExcluded, dirExcluded, notIncluded, git} {
		assertSource(t, path, nativeTestSource)
	}
	assertNoStagedFiles(t, dir)
}

func TestNativeInPlaceKeepsDetectorSelection(t *testing.T) {
	nativeBinary(t)
	requireInPlaceSecurity(t)
	for _, test := range []struct {
		name, include, exclude string
		redacted               bool
	}{
		{"include", "Github", "", true},
		{"other-detector", "Slack", "", false},
		{"exclude-wins", "Github,Slack", "Github", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			path := writeSource(t, dir, "original.go", nativeTestSource, 0600)
			result := nativeCommand(t, "--include-detectors="+test.include, "--exclude-detectors="+test.exclude, "filesystem", "--in-place", path)
			assertNativeFindings(t, result, 0)
			want := nativeTestSource
			if test.redacted {
				want = strings.ReplaceAll(want, nativeTestSecret, "REDACTED")
			}
			assertSource(t, path, want)
			assertNoStagedFiles(t, dir)
		})
	}
}

func TestNativeInPlaceFailuresPreserveSourceAndWithholdSecrets(t *testing.T) {
	nativeBinary(t)
	dir := t.TempDir()
	path := writeSource(t, dir, "original.go", nativeTestSource, 0600)
	controls := t.TempDir()
	malformed := writeSource(t, controls, "invalid.yaml", "detectors: ["+nativeTestSecret, 0600)
	badRules := writeSource(t, controls, "invalid-paths.txt", nativeTestSecret+"[\n", 0600)
	for _, test := range []struct {
		name string
		args []string
	}{
		{"zero-file-limit", []string{"--redaction-max-bytes=0", "filesystem", path}},
		{"zero-batch-limit", []string{"--redaction-max-total-bytes=0", "filesystem", path}},
		{"zero-file-count", []string{"--redaction-max-files=0", "filesystem", path}},
		{"zero-timeout", []string{"--redaction-timeout=0s", "filesystem", path}},
		{"file-too-large", []string{"--redaction-max-bytes=1", "filesystem", path}},
		{"batch-too-large", []string{"--redaction-max-total-bytes=1", "filesystem", path}},
		{"invalid-limit", []string{"--redaction-max-bytes=" + nativeTestSecret, "filesystem", path}},
		{"invalid-timeout", []string{"--redaction-timeout=" + nativeTestSecret, "filesystem", path}},
		{"invalid-detector", []string{"--include-detectors=" + nativeTestSecret, "filesystem", path}},
		{"invalid-config", []string{"--config", malformed, "filesystem", path}},
		{"invalid-path-rule", []string{"filesystem", "--include-paths", badRules, path}},
		{"git-source", []string{"git", dir}},
		{"stdin-source", []string{"stdin"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := nativeCommand(t, append([]string{"--in-place"}, test.args...)...)
			if result.code == 0 {
				t.Fatal("invalid native redaction request succeeded")
			}
			assertNativeStatus(t, result, result.code, true)
			assertSource(t, path, nativeTestSource)
			assertNoStagedFiles(t, dir)
		})
	}
}

func TestNativeInPlaceReportCannotTruncateInput(t *testing.T) {
	nativeBinary(t)
	for _, spelling := range []string{"--in-place", "--in-place=true", "--in-place=1", "--in-place=TRUE", "--in-place=t"} {
		t.Run(strings.TrimPrefix(spelling, "--"), func(t *testing.T) {
			dir := t.TempDir()
			path := writeSource(t, dir, "original.go", nativeTestSource, 0600)
			result := nativeCommand(t, spelling, "--output-report", path, "filesystem", path)
			if result.code == 0 {
				t.Fatal("source editing accepted an output-report target")
			}
			assertNativeStatus(t, result, result.code, true)
			assertSource(t, path, nativeTestSource)
			assertNoStagedFiles(t, dir)
		})
	}
	t.Run("argument-file", func(t *testing.T) {
		dir := t.TempDir()
		path := writeSource(t, dir, "original.go", nativeTestSource, 0600)
		arguments := writeSource(t, t.TempDir(), "arguments.txt", strings.Join([]string{"--in-place", "--output-report", path, "filesystem", path}, "\n")+"\n", 0600)
		result := nativeCommand(t, "@"+arguments)
		if result.code == 0 {
			t.Fatal("argument-file source editing accepted an output-report target")
		}
		assertNativeStatus(t, result, result.code, true)
		assertSource(t, path, nativeTestSource)
		assertNoStagedFiles(t, dir)
	})
	t.Run("malformed-argument-file", func(t *testing.T) {
		dir := t.TempDir()
		path := writeSource(t, dir, "original.go", nativeTestSource, 0600)
		// Put the invalid argument before edit mode: the parser may fail before
		// assigning its Bool pointer, but its diagnostic still contains a secret.
		arguments := writeSource(t, t.TempDir(), "arguments.txt", strings.Join([]string{"--redaction-max-bytes=" + nativeTestSecret, "--in-place", "filesystem", path}, "\n")+"\n", 0600)
		result := nativeCommand(t, "@"+arguments)
		if result.code == 0 {
			t.Fatal("malformed source argument-file request succeeded")
		}
		assertNativeStatus(t, result, result.code, true)
		assertSource(t, path, nativeTestSource)
		assertNoStagedFiles(t, dir)
	})
}

func TestNativeFalseInPlaceAssignmentsNeverEditSources(t *testing.T) {
	nativeBinary(t)
	for _, spelling := range []string{"--in-place=false", "--in-place=0", "--in-place=FALSE", "--in-place=f", "--no-in-place"} {
		t.Run(strings.TrimPrefix(spelling, "--"), func(t *testing.T) {
			dir := t.TempDir()
			path := writeSource(t, dir, "original.go", nativeTestSource, 0600)
			literalFalse := writeSource(t, dir, "false", nativeTestSource, 0600)
			for _, argumentFile := range []bool{false, true} {
				args := []string{"--include-detectors=Github", "filesystem", spelling, path}
				if argumentFile {
					arguments := writeSource(t, t.TempDir(), "arguments.txt", strings.Join(args, "\n")+"\n", 0600)
					args = []string{"@" + arguments}
				}
				result := nativeCommandAt(t, dir, args...)
				assertNativeFindings(t, result, 0)
				assertNativeJSONSecret(t, result)
				assertSource(t, path, nativeTestSource)
				assertSource(t, literalFalse, nativeTestSource)
				assertNoStagedFiles(t, dir)
			}
		})
	}
}

func TestNativeNestedArgumentFilesPreserveEditIntentAndBounds(t *testing.T) {
	nativeBinary(t)
	requireInPlaceSecurity(t)
	for _, enabled := range []bool{false, true} {
		t.Run(strconv.FormatBool(enabled), func(t *testing.T) {
			dir := t.TempDir()
			path := writeSource(t, dir, "original.go", nativeTestSource, 0600)
			literalFalse := writeSource(t, dir, "false", nativeTestSource, 0600)
			controls := t.TempDir()
			inner := writeSource(t, controls, "inner.txt", strings.Join([]string{"--include-detectors=Github", "filesystem", "--in-place=" + strconv.FormatBool(enabled), path}, "\n")+"\n", 0600)
			outer := writeSource(t, controls, "outer.txt", "# preserve native argument-file comments\n@"+inner+"\n", 0600)
			result := nativeCommandAt(t, dir, "@"+outer)
			assertNativeFindings(t, result, 0)
			assertNativeJSONSecret(t, result)
			want := nativeTestSource
			if enabled {
				want = strings.ReplaceAll(want, nativeTestSecret, "REDACTED")
			}
			assertSource(t, path, want)
			assertSource(t, literalFalse, nativeTestSource)
			assertNoStagedFiles(t, dir)
		})
	}
	for _, mode := range []string{"cycle", "oversized-line"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			path := writeSource(t, dir, "original.go", nativeTestSource, 0600)
			controls := t.TempDir()
			name := filepath.Join(controls, "arguments.txt")
			content := "@" + name + "\n"
			if mode == "oversized-line" {
				content = "--redaction-max-bytes=" + nativeTestSecret + strings.Repeat("x", 70<<10) + "\n--in-place\nfilesystem\n" + path + "\n"
			}
			writeSource(t, controls, "arguments.txt", content, 0600)
			result := nativeCommand(t, "@"+name)
			if result.code == 0 {
				t.Fatal("unbounded argument-file input succeeded")
			}
			assertNativeStatus(t, result, result.code, true)
			assertSource(t, path, nativeTestSource)
			assertNoStagedFiles(t, dir)
		})
	}
}
