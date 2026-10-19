//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
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

// Runners commonly expose TEMP through an existing 8.3 parent alias. Both
// complete short paths and mixed short/long components must remain usable.
func TestWindowsCanonicalPathAcceptsShortAliases(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "directory with long source name")
	path := writeSource(t, dir, "source with long name.go", "ordinary source", 0600)
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	name := make([]uint16, 32768)
	n, err := windows.GetShortPathName(ptr, &name[0], uint32(len(name)))
	if err != nil || n == 0 || n >= uint32(len(name)) {
		t.Skip("short path names are unavailable on this host")
	}
	short := windows.UTF16ToString(name[:n])
	if samePath(path, short) {
		t.Skip("the test volume did not provide an 8.3 alias")
	}
	for _, alias := range []string{
		filepath.Dir(short), short,
		filepath.Join(filepath.Dir(short), filepath.Base(path)),
		filepath.Join(dir, filepath.Base(short)),
	} {
		if !canonicalSourcePath(alias) {
			t.Fatal("a direct source path using an 8.3 alias was rejected")
		}
	}
}

func TestWindowsCanonicalPathRejectsJunctionAncestor(t *testing.T) {
	dir := t.TempDir()
	writeSource(t, dir, "source.go", "ordinary source", 0600)
	junction := filepath.Join(t.TempDir(), "linked-directory")
	if err := exec.Command("cmd", "/c", "mklink", "/J", junction, dir).Run(); err != nil {
		t.Skip("directory junctions are unavailable on this host")
	}
	defer os.Remove(junction)
	if canonicalSourcePath(junction) || canonicalSourcePath(filepath.Join(junction, "source.go")) {
		t.Fatal("a junction ancestor was accepted as a canonical source path")
	}
}
