//go:build !windows

package sourceredact

import (
	"context"
	"errors"
	"os"
)

const stageSourceFiles = true

func recoverSourceInputs(context.Context, []string, Options) error { return nil }

func commitFiles(ctx context.Context, root *os.Root, staged []stagedFile) error {
	for i, file := range staged {
		if err := ctx.Err(); err != nil {
			return rollback(root, staged[:i], err)
		}
		if !unchangedSource(root, file.path, file.original, file.originalInfo, file.security) {
			return rollback(root, staged[:i], errors.New("source changed before replacement; batch withheld"))
		}
		if file.temp == "" {
			continue
		}
		if !unchangedSource(root, file.temp, file.redacted, file.stagedInfo) {
			return rollback(root, staged[:i], errors.New("staged source changed before replacement; batch withheld"))
		}
		committedInfo, err := setStagedMode(root, file.temp, file.stagedInfo, file.mode, file.security)
		if err != nil {
			return rollback(root, staged[:i], errors.New("cannot preserve source permissions"))
		}
		staged[i].stagedInfo = committedInfo
		if err := root.Rename(file.temp, file.path); err != nil {
			return rollback(root, staged[:i], errors.New("cannot replace source file"))
		}
	}
	for _, file := range staged {
		expected := file.originalInfo
		if file.temp != "" {
			expected = file.stagedInfo
		}
		if !unchangedSource(root, file.path, file.redacted, expected, file.security) {
			return rollback(root, staged, errors.New("source changed during commit; do not forward this batch"))
		}
	}
	return nil
}

func rollback(root *os.Root, files []stagedFile, cause error) error {
	incomplete := false
	for i := len(files) - 1; i >= 0; i-- {
		file := files[i]
		if file.temp == "" {
			continue
		}
		if !unchangedSource(root, file.path, file.redacted, file.stagedInfo, file.security) {
			incomplete = true
			continue
		}
		temp, info, err := stageBytes(root, file.path, file.original)
		if err != nil {
			incomplete = true
			continue
		}
		_, modeErr := setStagedMode(root, temp, info, file.mode, file.security)
		if modeErr != nil || root.Rename(temp, file.path) != nil {
			_ = root.Remove(temp)
			incomplete = true
		}
	}
	if incomplete {
		return errors.New("source commit failed and rollback is incomplete; do not forward this batch")
	}
	return cause
}

func setStagedMode(root *os.Root, path string, expected os.FileInfo, mode os.FileMode, security ...securityMetadata) (os.FileInfo, error) {
	file, _, err := openRegularSource(root, path, expected, os.O_RDWR)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if len(security) > 0 && applySecurity(file, security[0]) != nil {
		return nil, errors.New("cannot preserve source security metadata")
	}
	if file.Chmod(mode.Perm()) != nil || (len(security) > 0 && !sameSecurity(file, security[0])) {
		return nil, errors.New("cannot preserve source permissions")
	}
	return finishStagedFile(root, path, file)
}
