package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"

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
	inlineInPlace  = cli.Flag("in-place", "Redact original local filesystem inputs after scanning, preserving ordinary findings and output flags. Use with filesystem.").Bool()
	inlineMaxBytes = cli.Flag("redaction-max-bytes", "Maximum bytes per file for --in-place; exceeding the limit fails.").Default("16777216").Int64()
	inlineMaxTotal = cli.Flag("redaction-max-total-bytes", "Maximum total source bytes for --in-place.").Default("268435456").Int64()
	inlineMaxFiles = cli.Flag("redaction-max-files", "Maximum files and directories for --in-place.").Default("10000").Int()
	inlineTimeout  = cli.Flag("redaction-timeout", "Time budget for --in-place scanning and commit; blocking reads/calls can overrun it.").Default("5m").Duration()
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
	pathFilter, skipDirectory, err := inlinePathFilter(*filesystemScanIncludePaths, *filesystemScanExcludePaths)
	if err != nil {
		return err
	}
	if *detectorTimeout != 0 {
		detectors.OverrideDetectorTimeout(*detectorTimeout)
	}
	paths := append(append([]string{}, *filesystemPaths...), *filesystemDirectories...)
	ctx, cancel := trContext.WithTimeout(ctx, *inlineTimeout)
	defer cancel()
	return sourceredact.RedactInPlace(ctx, scanner, paths, sourceredact.Options{
		MaxBytes: *inlineMaxBytes, MaxTotalBytes: *inlineMaxTotal, MaxFiles: *inlineMaxFiles,
		IncludePath: pathFilter, SkipDirectory: skipDirectory, NativePathFilters: true,
		BeforeCommit: func(scanCtx context.Context) error { return scan(trContext.AddLogger(scanCtx)) },
	})
}

// Match native include/exclude regex semantics, but never print config contents,
// and never call the ordinary filter loader's fatal exit during a transaction.
func inlinePathFilter(includeFile, excludeFile string) (func(string) bool, func(string) bool, error) {
	readRules := func(path string) ([]*re2.Regexp, error) {
		if path == "" {
			return nil, nil
		}
		data, err := inlineConfigBytes(path)
		if err != nil {
			return nil, err
		}
		var rules []*re2.Regexp
		ignoredLine := re2.MustCompile(`^\s*(#|$)`)
		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Buffer(make([]byte, 4096), len(data)+1)
		for scanner.Scan() {
			line := scanner.Text()
			if ignoredLine.MatchString(line) {
				continue
			}
			rule, err := re2.Compile(line)
			if err != nil || len(rules) >= 1024 {
				return nil, errors.New("invalid or excessive path filter rules")
			}
			rules = append(rules, rule)
		}
		if scanner.Err() != nil {
			return nil, errors.New("cannot read path filter rules")
		}
		return rules, nil
	}
	include, err := readRules(includeFile)
	if err != nil {
		return nil, nil, err
	}
	exclude, err := readRules(excludeFile)
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
