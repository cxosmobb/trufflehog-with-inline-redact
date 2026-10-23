//go:build windows

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/windows"
)

var reopenWindowsFile = windows.NewLazySystemDLL("kernel32.dll").NewProc("ReOpenFile")

type windowsSourceCommit struct {
	file   *os.File
	staged stagedFile
}

func commitFiles(ctx context.Context, root *os.Root, files []stagedFile) error {
	return commitWindowsFiles(ctx, root, files, rewriteWindowsSource)
}

// Keep the original file object instead of copying security metadata onto a
// replacement. Acquire every writer before changing any byte. The read-sharing
// locks exclude other writers/deleters while retaining ordinary read access.
func commitWindowsFiles(ctx context.Context, root *os.Root, files []stagedFile, rewrite func(*os.File, []byte) error) error {
	var commits []windowsSourceCommit
	defer func() {
		for _, commit := range commits {
			_ = commit.file.Close()
		}
	}()
	for _, staged := range files {
		if err := ctx.Err(); err != nil {
			return err
		}
		if staged.temp == "" {
			continue
		}
		file, err := openWindowsSource(root, staged)
		if err != nil {
			return err
		}
		commits = append(commits, windowsSourceCommit{file: file, staged: staged})
	}
	// Locks are held for the whole commit, including rollback and final checks.
	for _, staged := range files {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !unchangedSource(root, staged.path, staged.original, staged.originalInfo, staged.security) ||
			(staged.temp != "" && !unchangedSource(root, staged.temp, staged.redacted, staged.stagedInfo)) {
			return errors.New("source or stage changed before commit; batch withheld")
		}
	}
	for i, commit := range commits {
		if err := ctx.Err(); err != nil {
			return rollbackWindowsSources(root, commits[:i], err)
		}
		if !sameWindowsSource(root, commit) ||
			!unchangedSource(root, commit.staged.temp, commit.staged.redacted, commit.staged.stagedInfo) {
			return rollbackWindowsSources(root, commits[:i], errors.New("source or stage changed during commit; batch withheld"))
		}
		if err := rewrite(commit.file, commit.staged.redacted); err != nil {
			// A failed write can already have modified this file. Include it.
			return rollbackWindowsSources(root, commits[:i+1], err)
		}
		if err := ctx.Err(); err != nil {
			return rollbackWindowsSources(root, commits[:i+1], err)
		}
	}
	for _, staged := range files {
		if err := ctx.Err(); err != nil {
			return rollbackWindowsSources(root, commits, err)
		}
		if staged.temp == "" && !unchangedSource(root, staged.path, staged.original, staged.originalInfo, staged.security) {
			return rollbackWindowsSources(root, commits, errors.New("unchanged source changed during commit; do not forward this batch"))
		}
	}
	for _, commit := range commits {
		if err := ctx.Err(); err != nil {
			return rollbackWindowsSources(root, commits, err)
		}
		if !sameWindowsSource(root, commit) || !windowsContentEquals(commit.file, commit.staged.redacted) {
			return rollbackWindowsSources(root, commits, errors.New("source changed during commit; do not forward this batch"))
		}
	}
	if err := ctx.Err(); err != nil {
		return rollbackWindowsSources(root, commits, err)
	}
	return nil
}

func openWindowsSource(root *os.Root, staged stagedFile) (*os.File, error) {
	original, _, err := openRegularSource(root, staged.path, staged.originalInfo, os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer original.Close()
	// ReOpenFile is object-bound: reopening a pathname could follow an ancestor
	// substitution. A read-only initial handle avoids conflicting with our own
	// new handle's exclusion of shared writes.
	handle, _, _ := reopenWindowsFile.Call(original.Fd(), uintptr(windows.GENERIC_READ|windows.GENERIC_WRITE), uintptr(windows.FILE_SHARE_READ), 0)
	if handle == uintptr(windows.InvalidHandle) {
		return nil, errors.New("cannot acquire source write access; batch withheld")
	}
	file := os.NewFile(handle, original.Name())
	info, err := file.Stat()
	commit := windowsSourceCommit{file: file, staged: staged}
	if err != nil || !sameSource(staged.originalInfo, info) || !sameWindowsSource(root, commit) || !windowsContentEquals(file, staged.original) {
		_ = file.Close()
		return nil, errors.New("source identity, contents, links or permissions changed; batch withheld")
	}
	return file, nil
}

func sameWindowsSource(root *os.Root, commit windowsSourceCommit) bool {
	if !unchangedRoot(root) {
		return false
	}
	info, err := commit.file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode() != commit.staged.mode || !os.SameFile(info, commit.staged.originalInfo) {
		return false
	}
	named, err := root.Lstat(commit.staged.path)
	if err != nil || !sameSource(info, named) || !sameSecurity(commit.file, commit.staged.security) {
		return false
	}
	var native windows.ByHandleFileInformation
	return windows.GetFileInformationByHandle(windows.Handle(commit.file.Fd()), &native) == nil &&
		native.NumberOfLinks == 1 && native.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_READONLY) == 0
}

func windowsContentEquals(file *os.File, expected []byte) bool {
	before, err := file.Stat()
	if err != nil || before.Size() != int64(len(expected)) {
		return false
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return false
	}
	actual, err := readLimited(file, int64(len(expected)))
	after, statErr := file.Stat()
	return err == nil && statErr == nil && sameSource(before, after) && bytes.Equal(actual, expected)
}

func rewriteWindowsSource(file *os.File, data []byte) error {
	n, err := file.WriteAt(data, 0)
	if err != nil || n != len(data) {
		return errors.New("cannot write source contents")
	}
	if file.Truncate(int64(len(data))) != nil || file.Sync() != nil || !windowsContentEquals(file, data) {
		return errors.New("cannot finish or verify source contents")
	}
	return nil
}

func rollbackWindowsSources(root *os.Root, commits []windowsSourceCommit, cause error) error {
	incomplete := false
	for i := len(commits) - 1; i >= 0; i-- {
		commit := commits[i]
		// Never restore secret bytes to a substituted object or altered policy.
		// Retained write handles also cover the current partially written file.
		if !sameWindowsSource(root, commit) || rewriteWindowsSource(commit.file, commit.staged.original) != nil || !sameWindowsSource(root, commit) {
			incomplete = true
		}
	}
	if incomplete {
		return errors.New("source commit failed and rollback is incomplete; do not forward this batch")
	}
	return cause
}
