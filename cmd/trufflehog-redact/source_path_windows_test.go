//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsCanonicalPathAcceptsDirectFileAndDirectory(t *testing.T) {
	dir := t.TempDir()
	path := writeSource(t, dir, "source.go", "ordinary source", 0600)
	if !canonicalSourcePath(dir) || !canonicalSourcePath(path) {
		t.Fatal("direct NTFS source path was rejected")
	}
}

func TestWindowsCanonicalPathRejectsFileAndAncestorSymlinks(t *testing.T) {
	dir := t.TempDir()
	target := writeSource(t, dir, "source.go", "ordinary source", 0600)
	link := filepath.Join(dir, "link.go")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symbolic links are unavailable on this host")
	}
	if canonicalSourcePath(link) {
		t.Fatal("a final symlink was accepted as a canonical source path")
	}
	ancestor := filepath.Join(t.TempDir(), "linked-dir")
	if err := os.Symlink(dir, ancestor); err != nil {
		t.Skip("directory symbolic links are unavailable on this host")
	}
	if canonicalSourcePath(filepath.Join(ancestor, "source.go")) {
		t.Fatal("a symlink ancestor was accepted as a canonical source path")
	}
}
