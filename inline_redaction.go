package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/internal/sourceredact"
	"github.com/trufflesecurity/trufflehog/v3/pkg/config"
	trContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
	"github.com/trufflesecurity/trufflehog/v3/pkg/redaction"
)

var (
	inlineInPlace         = cli.Flag("in-place", "Redact original local filesystem inputs after scanning, preserving ordinary findings and output flags. Use with filesystem.").Bool()
	inlineValidateFilters = cli.Flag("internal-validate-redaction-filters", "Validate source-redaction path filters in an isolated process.").Hidden().Bool()
	inlineMaxBytes        = cli.Flag("redaction-max-bytes", "Maximum bytes per file for --in-place; exceeding the limit fails.").Default("16777216").Int64()
	inlineMaxTotal        = cli.Flag("redaction-max-total-bytes", "Maximum total source bytes for --in-place.").Default("268435456").Int64()
	inlineMaxFiles        = cli.Flag("redaction-max-files", "Maximum files and directories for --in-place.").Default("10000").Int()
	inlineTimeout         = cli.Flag("redaction-timeout", "Time budget for --in-place scanning and commit; blocking reads/calls can overrun it.").Default("5m").Duration()
)

// Keep parser diagnostics secret-free for an edit request, including malformed
// boolean assignments and @argument files whose flags have not been applied yet.
func inlineRequested(args []string) bool {
	for _, arg := range args {
		if arg == "--" {
			break
		}
		if arg == "--in-place" || strings.HasPrefix(arg, "--in-place=") || strings.HasPrefix(arg, "@") {
			return true
		}
	}
	return false
}

// Expand argument files once, following kingpin's one-argument-per-line format.
// Normalize this destructive flag's assignments because kingpin otherwise treats
// their value as a source path and enables the flag even for '=false'.
func inlineArguments(args []string) ([]string, error) {
	var output []string
	remaining, count, literal := 1<<20, 0, false
	var expand func([]string, int) error
	expand = func(args []string, depth int) error {
		if depth > 8 {
			return errors.New("argument-file nesting exceeds limit")
		}
		for _, arg := range args {
			count++
			if count > 10000 {
				return errors.New("argument count exceeds limit")
			}
			if !literal && strings.HasPrefix(arg, "@") {
				file, err := os.Open(arg[1:])
				if err != nil {
					return errors.New("cannot read argument file")
				}
				data, readErr := io.ReadAll(io.LimitReader(file, int64(remaining)+1))
				closeErr := file.Close()
				if readErr != nil || closeErr != nil || len(data) > remaining {
					return errors.New("argument files exceed limit or are unreadable")
				}
				remaining -= len(data)
				var nested []string
				scanner := bufio.NewScanner(bytes.NewReader(data))
				for scanner.Scan() {
					line := scanner.Text()
					if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
						continue
					}
					if len(nested)+count >= 10000 {
						return errors.New("argument count exceeds limit")
					}
					nested = append(nested, line)
				}
				if scanner.Err() != nil {
					return errors.New("argument-file line exceeds limit")
				}
				if err := expand(nested, depth+1); err != nil {
					return err
				}
				continue
			}
			if !literal {
				name, value, assigned := strings.Cut(arg, "=")
				name = strings.ReplaceAll(name, "_", "-")
				if assigned && (name == "--in-place" || name == "--no-in-place") {
					enabled, err := strconv.ParseBool(value)
					if err != nil {
						return errors.New("invalid in-place flag assignment")
					}
					if name == "--no-in-place" {
						enabled = !enabled
					}
					arg = "--no-in-place"
					if enabled {
						arg = "--in-place"
					}
				}
				literal = arg == "--"
			}
			output = append(output, arg)
		}
		return nil
	}
	if err := expand(args, 0); err != nil {
		return nil, err
	}
	return output, nil
}

// Plan source edits before the ordinary scan, then commit only when that scan
// and the transaction's repeated identity/content checks have succeeded.
func runInlineRedaction(ctx trContext.Context, conf *config.Config, scan func(trContext.Context) error) error {
	if *jobReportFile != "" {
		return errors.New("--output-report is only available for ordinary scans")
	}
	if cmd != filesystemScan.FullCommand() {
		return errors.New("--in-place requires filesystem and local paths; repository history and remote sources are not rewritten")
	}
	if *filesystemScanMaxSymlinkDepth != 0 {
		return errors.New("--in-place cannot follow symbolic links")
	}
	if *inlineMaxBytes <= 0 || *inlineMaxTotal <= 0 || *inlineMaxFiles <= 0 || *inlineTimeout <= 0 {
		return errors.New("redaction limits and timeout must be positive")
	}
	selected, err := engine.SelectDetectors(append(defaults.RedactionDetectors(), conf.Detectors...), *includeDetectors, *excludeDetectors)
	if err != nil {
		return errors.New("invalid detector selection")
	}
	scanner, err := redaction.New(selected)
	if err != nil {
		return err
	}
	ctx, cancel := trContext.WithTimeout(ctx, *inlineTimeout)
	defer cancel()
	pathFilter, skipDirectory, err := inlinePathFilter(ctx, *filesystemScanIncludePaths, *filesystemScanExcludePaths)
	if err != nil {
		return err
	}
	if *detectorTimeout != 0 {
		detectors.OverrideDetectorTimeout(*detectorTimeout)
	}
	paths := append(append([]string{}, *filesystemPaths...), *filesystemDirectories...)
	return sourceredact.RedactInPlace(ctx, scanner, paths, sourceredact.Options{
		MaxBytes: *inlineMaxBytes, MaxTotalBytes: *inlineMaxTotal, MaxFiles: *inlineMaxFiles,
		IncludePath: pathFilter, SkipDirectory: skipDirectory, NativePathFilters: true,
		BeforeCommit: func(scanCtx context.Context) error { return scan(trContext.AddLogger(scanCtx)) },
	})
}

// Match native include/exclude regex semantics, but never print config contents,
// and never call the ordinary filter loader's fatal exit during a transaction.
func inlinePathFilter(ctx context.Context, includeFile, excludeFile string) (func(string) bool, func(string) bool, error) {
	readRules := func(path string) ([]string, error) {
		if path == "" {
			return nil, nil
		}
		data, err := inlineConfigBytes(path)
		if err != nil {
			return nil, err
		}
		var rules []string
		ignoredLine := re2.MustCompile(`^\s*(#|$)`)
		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Buffer(make([]byte, 4096), len(data)+1)
		for scanner.Scan() {
			line := scanner.Text()
			if ignoredLine.MatchString(line) {
				continue
			}
			if len(rules) >= 1024 {
				return nil, errors.New("invalid or excessive path filter rules")
			}
			rules = append(rules, line)
		}
		if scanner.Err() != nil {
			return nil, errors.New("cannot read path filter rules")
		}
		return rules, nil
	}
	includePatterns, err := readRules(includeFile)
	if err != nil {
		return nil, nil, err
	}
	excludePatterns, err := readRules(excludeFile)
	if err != nil {
		return nil, nil, err
	}
	patterns := append(append([]string{}, includePatterns...), excludePatterns...)
	if err := checkInlineFilterPatterns(ctx, patterns); err != nil {
		return nil, nil, err
	}
	compileRules := func(patterns []string) ([]*re2.Regexp, error) {
		rules := make([]*re2.Regexp, 0, len(patterns))
		for _, pattern := range patterns {
			rule, err := re2.Compile(pattern)
			if err != nil {
				return nil, errors.New("invalid path filter rules")
			}
			rules = append(rules, rule)
		}
		return rules, nil
	}
	include, err := compileRules(includePatterns)
	if err != nil {
		return nil, nil, err
	}
	exclude, err := compileRules(excludePatterns)
	if err != nil {
		return nil, nil, err
	}
	matches := func(rules []*re2.Regexp, path string) bool {
		for _, rule := range rules {
			if rule.MatchString(path) {
				return true
			}
		}
		return false
	}
	return func(path string) bool {
			return !matches(exclude, path) && (includeFile == "" || matches(include, path))
		}, func(path string) bool {
			return matches(exclude, path)
		}, nil
}

// The RE2 backend logs malformed patterns directly to stderr even when its
// returned error is discarded. Validate both files in one isolated invocation
// of this executable before compiling in the parent. Patterns travel only over
// stdin, and the child's output is discarded; accepted syntax stays native RE2.
func checkInlineFilterPatterns(ctx context.Context, patterns []string) error {
	if len(patterns) == 0 {
		return nil
	}
	// JSON replaces invalid UTF-8; reject it before transport so the child
	// validates exactly the bytes later passed to the UTF-8 RE2 compiler.
	for _, pattern := range patterns {
		if !utf8.ValidString(pattern) {
			return errors.New("invalid path filter rules")
		}
	}
	data, err := json.Marshal(patterns)
	if err != nil {
		return errors.New("cannot validate path filter rules")
	}
	executable, err := os.Executable()
	if err != nil {
		return errors.New("cannot validate path filter rules")
	}
	executable, err = filepath.Abs(executable)
	if err != nil {
		return errors.New("cannot validate path filter rules")
	}
	child := exec.CommandContext(ctx, executable, "--no-update", "--internal-validate-redaction-filters", "filesystem")
	child.Env = append(os.Environ(), "TRUFFLEHOG_INTERNAL_FILTER_VALIDATION=1")
	child.Stdin = bytes.NewReader(data)
	child.Stdout, child.Stderr = io.Discard, io.Discard
	if err := child.Run(); err != nil {
		return errors.New("invalid path filter rules or validation failed")
	}
	return nil
}

// validateInlineFilters is the isolated helper's entire operation. Its caller
// exits before logger, updater, source scanning or transaction initialization.
func validateInlineFilters(input io.Reader) int {
	data, err := io.ReadAll(io.LimitReader(input, (16<<20)+1))
	if err != nil || len(data) > 16<<20 {
		return 1
	}
	var patterns []string
	if err := json.Unmarshal(data, &patterns); err != nil || len(patterns) > 2048 {
		return 1
	}
	total := 0
	for _, pattern := range patterns {
		if len(pattern) > (2<<20)-total {
			return 1
		}
		total += len(pattern)
	}
	for _, pattern := range patterns {
		if _, err := re2.Compile(pattern); err != nil {
			return 1
		}
	}
	return 0
}

func inlineConfigBytes(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot read redaction configuration or path filter")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return nil, errors.New("redaction configuration or path filter exceeds limit or is unreadable")
	}
	return data, nil
}
