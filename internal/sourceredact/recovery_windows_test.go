//go:build windows

package sourceredact

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/redaction"
	"golang.org/x/sys/windows"
)

type windowsRecoveryBoundsFixture struct {
	root           *os.Root
	relative, path string
	original       []byte
}

func newWindowsRecoveryBoundsFixture(t *testing.T) windowsRecoveryBoundsFixture {
	t.Helper()
	fixture := newWindowsCrashFixture(t, false)
	root, err := openSourceRoot(fixture.paths)
	if err != nil {
		t.Fatal("cannot pin recovery bounds fixture")
	}
	t.Cleanup(func() { _ = root.Close() })
	path := fixture.paths[1]
	relative, err := filepath.Rel(root.Name(), path)
	if err != nil {
		t.Fatal("cannot resolve recovery bounds fixture")
	}
	staged := stagedFile{path: relative, original: fixture.originals[1],
		redacted: bytes.ReplaceAll(fixture.originals[1], []byte(fixture.secret), []byte(redaction.Marker)),
		mode:     fixture.info[1].Mode(), originalInfo: fixture.info[1], security: fixture.security[1]}
	file, err := openWindowsSource(root, staged)
	if err != nil {
		t.Fatal("cannot lock recovery bounds fixture")
	}
	defer file.Close()
	journal, err := prepareWindowsRecovery(root, windowsSourceCommit{file: file, staged: staged})
	if err != nil {
		t.Fatal("cannot prepare recovery bounds fixture")
	}
	journal.close() // Leave a genuine authenticated, armed record on original bytes.
	return windowsRecoveryBoundsFixture{root: root, relative: relative, path: path, original: fixture.originals[1]}
}

func (fixture windowsRecoveryBoundsFixture) assertRejected(t *testing.T, maxBytes int64, remaining *int64) {
	t.Helper()
	writes := 0
	rewrite := func(*os.File, []byte) error {
		writes++
		return errors.New("a rejected recovery must not write")
	}
	if recovered, err := recoverWindowsSourceWithBudget(fixture.root, fixture.relative, maxBytes, rewrite, remaining); recovered || !errors.Is(err, errWindowsRecovery) || writes != 0 {
		t.Fatal("recovery bounds did not withhold source writes")
	}
	assertSource(t, fixture.path, string(fixture.original))
	for _, suffix := range []string{windowsRecoveryDataStream, windowsRecoveryReadyStream} {
		if _, err := os.Stat(fixture.path + suffix); err != nil {
			t.Fatal("rejected recovery discarded its journal")
		}
	}
}

func TestWindowsRecoveryBoundsRejectOversizedSparseJournalBeforeAllocation(t *testing.T) {
	fixture := newWindowsRecoveryBoundsFixture(t)
	source, err := fixture.root.Open(fixture.relative)
	if err != nil {
		t.Fatal("cannot pin sparse journal source")
	}
	defer source.Close()
	stream, err := openWindowsRecoveryStream(source, windowsRecoveryDataStream, windows.OPEN_EXISTING)
	if err != nil {
		t.Fatal("cannot open sparse journal fixture")
	}
	var returned uint32
	if err := windows.DeviceIoControl(windows.Handle(stream.Fd()), windows.FSCTL_SET_SPARSE, nil, 0, nil, 0, &returned, nil); err != nil {
		_ = stream.Close()
		t.Fatal("cannot make the NTFS journal fixture sparse")
	}
	// Increase only logical size; no large input buffer or physical write.
	truncateErr := stream.Truncate(int64(windowsRecoveryMaxCipher) + 1)
	closeErr := stream.Close()
	if truncateErr != nil || closeErr != nil {
		t.Fatal("cannot extend sparse journal fixture")
	}
	remaining := int64(windowsRecoveryMaxCipher) * 2
	beforeBudget := remaining
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	fixture.assertRejected(t, 1<<20, &remaining)
	runtime.ReadMemStats(&after)
	if remaining != beforeBudget {
		t.Fatal("oversized journal was charged after its metadata should have refused it")
	}
	if after.TotalAlloc-before.TotalAlloc > 8<<20 {
		t.Fatal("oversized sparse journal was allocated before rejection")
	}
}

func TestWindowsRecoveryBoundsRejectInsufficientCipherBudget(t *testing.T) {
	fixture := newWindowsRecoveryBoundsFixture(t)
	info, err := os.Stat(fixture.path + windowsRecoveryDataStream)
	if err != nil || info.Size() < 2 {
		t.Fatal("cannot size encrypted journal fixture")
	}
	remaining := info.Size() - 1
	beforeBudget := remaining
	fixture.assertRejected(t, 1<<20, &remaining)
	if remaining != beforeBudget {
		t.Fatal("refused journal consumed the shared ciphertext budget")
	}
}

func TestWindowsRecoveryBoundsRejectOriginalAboveConfiguredLimit(t *testing.T) {
	fixture := newWindowsRecoveryBoundsFixture(t)
	fixture.assertRejected(t, 1, nil)
}
