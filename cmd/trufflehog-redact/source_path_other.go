//go:build !windows

package main

import "path/filepath"

func canonicalSourcePath(path string) bool {
	resolved, err := filepath.EvalSymlinks(path)
	return err == nil && samePath(path, resolved)
}
