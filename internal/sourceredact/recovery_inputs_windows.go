//go:build windows

package sourceredact

import (
	"context"
	"math"
	"path/filepath"
)

// Recovery cannot depend on finding the original credential or on today's
// reporting/path filters. Inspect the explicit input roots before scanning.
func recoverSourceInputs(ctx context.Context, inputs []string, options Options) error {
	files, err := sourceFilesSelected(ctx, inputs, options.MaxFiles, nil, nil, false)
	if err != nil {
		return err
	}
	root, err := openSourceRoot(files)
	if err != nil {
		return err
	}
	defer root.Close()
	var recoveredBytes int64
	journalBudget := int64(math.MaxInt64)
	if options.MaxTotalBytes <= (math.MaxInt64-(16<<20))/16 {
		journalBudget = options.MaxTotalBytes*16 + (16 << 20)
	}
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return err
		}
		relative, err := filepath.Rel(root.Name(), file)
		if err != nil {
			return errWindowsRecovery
		}
		recovered, err := recoverWindowsSourceWithBudget(root, relative, min(options.MaxBytes, options.MaxTotalBytes-recoveredBytes), rewriteWindowsSource, &journalBudget)
		if err != nil {
			return err
		}
		if recovered {
			info, err := root.Stat(relative)
			if err != nil || info.Size() > options.MaxTotalBytes-recoveredBytes {
				return errWindowsRecovery
			}
			recoveredBytes += info.Size()
		}
	}
	return nil
}
