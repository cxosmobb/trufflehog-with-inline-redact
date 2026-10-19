//go:build windows

package main

import (
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

// Resolve the already-open object, rather than opening every ancestor as
// EvalSymlinks does. Windows may grant access to an import directory without
// granting directory-listing rights on all of its parents.
func canonicalSourcePath(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	name := make([]uint16, 32768)
	n, err := windows.GetFinalPathNameByHandle(windows.Handle(file.Fd()), &name[0], uint32(len(name)), 0)
	if err != nil || n == 0 || n >= uint32(len(name)) {
		return false
	}
	resolved := windows.UTF16ToString(name[:n])
	if strings.HasPrefix(resolved, `\\?\UNC\`) {
		resolved = `\\` + strings.TrimPrefix(resolved, `\\?\UNC\`)
	} else {
		resolved = strings.TrimPrefix(resolved, `\\?\`)
	}
	return samePath(path, resolved)
}
