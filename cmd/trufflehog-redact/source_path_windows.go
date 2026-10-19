//go:build windows

package main

import (
	"os"
	"path/filepath"
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
	resolved := windowsDOSPath(windows.UTF16ToString(name[:n]))
	if samePath(path, resolved) {
		return true
	}

	// Derive allowed 8.3 aliases from the resolved target, never by resolving
	// the caller's spelling. A symlink or junction must still compare unequal.
	// Keep the direct-path fast path above: alias queries may need parent access.
	short := make([]uint16, 32768)
	n, err = windows.GetShortPathName(&name[0], &short[0], uint32(len(short)))
	if err != nil || n == 0 || n >= uint32(len(short)) {
		return false
	}
	parts := strings.Split(filepath.Clean(windowsDOSPath(path)), `\`)
	longParts := strings.Split(filepath.Clean(resolved), `\`)
	shortParts := strings.Split(filepath.Clean(windowsDOSPath(windows.UTF16ToString(short[:n]))), `\`)
	if len(parts) != len(longParts) || len(parts) != len(shortParts) {
		return false
	}
	for i, part := range parts {
		if !strings.EqualFold(part, longParts[i]) && !strings.EqualFold(part, shortParts[i]) {
			return false
		}
	}
	return true
}

func windowsDOSPath(path string) string {
	if strings.HasPrefix(path, `\\?\UNC\`) {
		return `\\` + strings.TrimPrefix(path, `\\?\UNC\`)
	}
	return strings.TrimPrefix(path, `\\?\`)
}
