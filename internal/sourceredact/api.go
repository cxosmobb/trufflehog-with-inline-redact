package sourceredact

import (
	"context"
	"errors"
	"io"
)

// Options bounds the selected source files and the work needed to process them.
// IncludePath receives absolute file names unless NativePathFilters is enabled.
// Directory validation and traversal remain mandatory even when their files are
// excluded. SkipDirectory prunes matching real directories after their metadata
// and count have been checked.
type Options struct {
	MaxBytes      int64
	MaxTotalBytes int64
	MaxFiles      int
	IncludePath   func(string) bool
	SkipDirectory func(string) bool
	// NativePathFilters preserves each input's cleaned spelling when matching
	// its descendants, and bypasses IncludePath for explicit file arguments,
	// following the native filesystem source's selection semantics.
	NativePathFilters bool
	// BeforeCommit runs after every edit has been planned and input validated,
	// before private stage files exist. An error withholds the entire batch.
	BeforeCommit func(context.Context) error
}

// Defaults returns the limits used by the standalone source redaction command.
func Defaults() Options {
	return Options{MaxBytes: 16 << 20, MaxTotalBytes: 256 << 20, MaxFiles: 10000}
}

// RedactInPlace scans the complete selected batch before modifying any source.
// Callers supply an offline scanner and must withhold the batch on any error.
func RedactInPlace(ctx context.Context, scanner Scanner, paths []string, options Options) error {
	if scanner == nil {
		return errors.New("source redaction scanner is required")
	}
	if options.MaxBytes < 1 || options.MaxTotalBytes < 1 || options.MaxFiles < 1 {
		return errors.New("source redaction limits must be positive")
	}
	if err := recoverSourceInputs(ctx, paths, options); err != nil {
		return err
	}
	files, err := sourceFilesSelected(ctx, paths, options.MaxFiles, options.IncludePath, options.SkipDirectory, options.NativePathFilters)
	if err != nil {
		return err
	}
	return redactFilesWithOptions(ctx, scanner, files, options.MaxBytes, options.MaxTotalBytes, options.BeforeCommit)
}

// Run retains the standalone source-stream and in-place command interface.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	return run(args, stdin, stdout, stderr)
}
