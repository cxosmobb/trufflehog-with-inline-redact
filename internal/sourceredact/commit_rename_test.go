//go:build !windows

package sourceredact

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestRollbackRestoresOriginalAndContinuesPastBlockedFile(t *testing.T) {
	requireInPlaceSecurity(t)
	dir := t.TempDir()
	first := writeSource(t, dir, "first.go", "REDACTED first", 0600)
	second := writeSource(t, dir, "second.go", "external amendment", 0600)
	root, err := openSourceRoot([]string{first, second})
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	firstInfo, err := root.Stat("first.go")
	if err != nil {
		t.Fatal(err)
	}
	firstFile, err := root.Open("first.go")
	if err != nil {
		t.Fatal(err)
	}
	firstSecurity, err := captureSecurity(firstFile)
	_ = firstFile.Close()
	if err != nil {
		t.Fatal(err)
	}
	files := []stagedFile{
		{path: "first.go", temp: "already-committed-first", original: []byte("SYNTHETIC_SECRET first"), redacted: []byte("REDACTED first"), mode: 0600, stagedInfo: firstInfo, security: firstSecurity},
		{path: "second.go", temp: "already-committed-second", original: []byte("SYNTHETIC_SECRET second"), redacted: []byte("REDACTED second"), mode: 0600},
	}
	if err := rollback(root, files, errors.New("synthetic commit failure")); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatal("incomplete rollback was not reported")
	}
	assertSource(t, first, "SYNTHETIC_SECRET first")
	assertSource(t, second, "external amendment")
	assertNoStagedFiles(t, dir)
}

func TestStagedMetadataSurvivesRename(t *testing.T) {
	requireInPlaceSecurity(t)
	dir := t.TempDir()
	path := writeSource(t, dir, "source.go", "original", 0600)
	root, err := openSourceRoot([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	temp, info, err := stageBytes(root, "source.go", []byte("replacement"))
	if err != nil {
		t.Fatal(err)
	}
	info, err = setStagedMode(root, temp, info, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := root.Rename(temp, "source.go"); err != nil {
		t.Fatal(err)
	}
	current, err := root.Stat("source.go")
	if err != nil {
		t.Fatal(err)
	}
	if !sameSource(info, current) {
		t.Fatalf("metadata changed after rename: identity=%v modes=%v/%v sizes=%d/%d times=%v/%v", os.SameFile(info, current), info.Mode(), current.Mode(), info.Size(), current.Size(), info.ModTime(), current.ModTime())
	}
}
