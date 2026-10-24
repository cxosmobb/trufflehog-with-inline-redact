//go:build windows

package sourceredact

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/redaction"
	"golang.org/x/sys/windows"
)

// Crash points exist only in this test executable. The parent kills a blocked
// child after a partial WriteAt has been flushed, so no deferred rollback runs.
func TestWindowsCrashRecoveryProcess(t *testing.T) {
	if os.Getenv("TRUFFLEHOG_REDACT_CRASH_PROCESS") != "1" {
		return
	}
	dir := os.Getenv("TRUFFLEHOG_REDACT_CRASH_DIRECTORY")
	mode := os.Getenv("TRUFFLEHOG_REDACT_CRASH_MODE")
	secret := "SYNTHETIC_SECRET"
	if os.Getenv("TRUFFLEHOG_REDACT_CRASH_NATIVE") == "1" {
		secret = nativeTestSecret
	}
	originals := windowsCrashSourceBytes(secret)
	maxBytes := int64(1 << 20)
	if os.Getenv("TRUFFLEHOG_REDACT_CRASH_LARGE") == "1" {
		maxBytes = 64 << 20
	}
	paths := []string{filepath.Join(dir, "first.go"), filepath.Join(dir, "nested", "second.go")}
	root, err := openSourceRoot(paths)
	if err != nil {
		t.Fatal("cannot pin crash fixture")
	}
	defer root.Close()
	if mode == "retry" || mode == "retry-filtered" {
		calls := 0
		scanner := sourceScannerFunc(func(_ context.Context, data []byte) ([]byte, redaction.Report, error) {
			if !bytes.Equal(data, originals[0]) && !bytes.Equal(data, originals[1]) {
				return nil, redaction.Report{}, errors.New("recovery did not restore the original before scanning")
			}
			calls++
			return bytes.ReplaceAll(data, []byte(secret), []byte(redaction.Marker)), redaction.Report{}, nil
		})
		options := Defaults()
		if os.Getenv("TRUFFLEHOG_REDACT_CRASH_LARGE") == "1" {
			options.MaxBytes = maxBytes
		}
		expectedCalls := len(paths)
		if mode == "retry-filtered" {
			expectedCalls = 1
			options.IncludePath = func(path string) bool { return filepath.Base(path) == "first.go" }
		}
		options.BeforeCommit = func(context.Context) error {
			for i, path := range paths {
				data, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(data, originals[i]) {
					return errors.New("native scan callback observed unrecovered input")
				}
			}
			return nil
		}
		if err := RedactInPlace(context.Background(), scanner, []string{dir}, options); err != nil {
			t.Fatal("retry after interrupted write failed")
		}
		if calls != expectedCalls {
			t.Fatal("retry did not scan exactly the original source files")
		}
		return
	}
	calls := 0
	write := func(file *os.File, data []byte) error {
		calls++
		if calls == 2 {
			if mode == "commit-complete" {
				if err := rewriteWindowsSource(file, data); err != nil {
					return err
				}
			} else {
				fraction := 2
				if mode == "recover-partial" {
					fraction = 4
				}
				if n, err := file.WriteAt(data[:len(data)/fraction], 0); err != nil || n != len(data)/fraction || file.Sync() != nil {
					return errors.New("cannot flush interrupted test write")
				}
			}
			windowsCrashPause(t)
		}
		return rewriteWindowsSource(file, data)
	}
	if mode == "recover-partial" {
		for _, path := range paths {
			relative, err := filepath.Rel(root.Name(), path)
			if err != nil {
				t.Fatal("cannot resolve recovery fixture")
			}
			if recovered, err := recoverWindowsSource(root, relative, maxBytes, write); err != nil || !recovered {
				t.Fatal("cannot reach interrupted recovery write")
			}
		}
		t.Fatal("recovery did not reach its crash point")
	}
	if mode != "commit-partial" && mode != "commit-complete" && mode != "cleanup-partial" {
		t.Fatal("invalid crash test mode")
	}
	var staged []stagedFile
	for i, path := range paths {
		relative, err := filepath.Rel(root.Name(), path)
		if err != nil {
			t.Fatal("cannot resolve crash fixture")
		}
		file, info, err := openRegularSource(root, relative, nil, os.O_RDONLY)
		if err != nil {
			t.Fatal("cannot open crash fixture")
		}
		security, captureErr := captureSecurity(file)
		_ = file.Close()
		if captureErr != nil {
			t.Fatal("cannot capture crash fixture policy")
		}
		staged = append(staged, stagedFile{
			path: relative, original: originals[i], redacted: bytes.ReplaceAll(originals[i], []byte(secret), []byte(redaction.Marker)),
			mode: info.Mode(), originalInfo: info, security: security,
		})
	}
	if mode == "cleanup-partial" {
		file, err := openWindowsSource(root, staged[1])
		if err != nil {
			t.Fatal("cannot lock journal cleanup fixture")
		}
		defer file.Close()
		journal, err := prepareWindowsRecovery(root, windowsSourceCommit{file: file, staged: staged[1]})
		if err != nil {
			t.Fatal("cannot prepare journal cleanup fixture")
		}
		defer journal.close()
		if rewriteWindowsSource(file, staged[1].redacted) != nil {
			t.Fatal("cannot finish journal cleanup fixture")
		}
		remove := byte(1)
		if windows.SetFileInformationByHandle(windows.Handle(journal.ready.Fd()), windows.FileDispositionInfo, &remove, 1) != nil || journal.ready.Close() != nil {
			t.Fatal("cannot disarm completed journal")
		}
		journal.ready = nil
		if file.Sync() != nil {
			t.Fatal("cannot flush journal disarming")
		}
		windowsCrashPause(t)
	}
	if err := commitWindowsFiles(context.Background(), root, staged, write); err != nil {
		t.Fatal("cannot reach interrupted commit write")
	}
	t.Fatal("commit did not reach its crash point")
}

func windowsCrashPause(t *testing.T) {
	t.Helper()
	marker, err := os.OpenFile(os.Getenv("TRUFFLEHOG_REDACT_CRASH_READY"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal("cannot signal crash boundary")
	}
	_, writeErr := io.WriteString(marker, "ready")
	syncErr := marker.Sync()
	closeErr := marker.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		t.Fatal("cannot flush crash boundary")
	}
	// The parent's Process.Kill, rather than an orderly exit, is the test.
	for {
		time.Sleep(time.Hour)
	}
}

func windowsCrashSourceBytes(secret string) [][]byte {
	body := strings.Repeat("0123456789abcdef", 1024)
	secondBody := body
	if os.Getenv("TRUFFLEHOG_REDACT_CRASH_LARGE") == "1" {
		secondBody = strings.Repeat("0123456789abcdef", (33<<20)/16)
	}
	return [][]byte{
		[]byte("// first prefix " + secret + " " + body + " first suffix\r\n"),
		[]byte("// second prefix " + secret + " " + secondBody + " tail " + secret + " second suffix\r\n"),
	}
}

type windowsCrashFixture struct {
	dir, control, secret string
	paths                []string
	originals            [][]byte
	info                 []os.FileInfo
	security             []securityMetadata
}

func newWindowsCrashFixture(t *testing.T, native bool) windowsCrashFixture {
	t.Helper()
	owned := t.TempDir()
	privateWindowsTestDirectory(t, owned)
	fixture := windowsCrashFixture{dir: filepath.Join(owned, "input"), control: filepath.Join(owned, "control"), secret: "SYNTHETIC_SECRET"}
	if native {
		fixture.secret = nativeTestSecret
	}
	fixture.originals = windowsCrashSourceBytes(fixture.secret)
	if err := os.MkdirAll(fixture.control, 0700); err != nil {
		t.Fatal("cannot create crash controls")
	}
	for i, name := range []string{"first.go", filepath.Join("nested", "second.go")} {
		path := writeSource(t, fixture.dir, name, string(fixture.originals[i]), 0600)
		if err := os.WriteFile(path+":retained-metadata", []byte("preserved stream metadata"), 0600); err != nil {
			t.Fatal("cannot create retained alternate stream")
		}
		file, err := os.Open(path)
		if err != nil {
			t.Fatal("cannot inspect crash source")
		}
		info, statErr := file.Stat()
		security, securityErr := captureSecurity(file)
		_ = file.Close()
		if statErr != nil || securityErr != nil {
			t.Fatal("cannot inspect crash source policy")
		}
		fixture.paths = append(fixture.paths, path)
		fixture.info = append(fixture.info, info)
		fixture.security = append(fixture.security, security)
	}
	return fixture
}

type windowsCrashChild struct {
	command *exec.Cmd
	cancel  context.CancelFunc
	done    chan error
	output  *bytes.Buffer
	waited  bool
}

func startWindowsCrashChild(t *testing.T, fixture windowsCrashFixture, mode string) *windowsCrashChild {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal("cannot locate crash test executable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	command := exec.CommandContext(ctx, binary, "-test.run=^TestWindowsCrashRecoveryProcess$", "-test.timeout=40s")
	native := "0"
	if fixture.secret == nativeTestSecret {
		native = "1"
	}
	command.Env = append(os.Environ(), "TRUFFLEHOG_REDACT_CRASH_PROCESS=1", "TRUFFLEHOG_REDACT_CRASH_DIRECTORY="+fixture.dir,
		"TRUFFLEHOG_REDACT_CRASH_MODE="+mode, "TRUFFLEHOG_REDACT_CRASH_READY="+filepath.Join(fixture.control, mode+".ready"), "TRUFFLEHOG_REDACT_CRASH_NATIVE="+native)
	output := new(bytes.Buffer)
	command.Stdout, command.Stderr = output, output
	if err := command.Start(); err != nil {
		cancel()
		t.Fatal("cannot launch crash test process")
	}
	child := &windowsCrashChild{command: command, cancel: cancel, done: make(chan error, 1), output: output}
	go func() { child.done <- command.Wait() }()
	t.Cleanup(func() {
		cancel()
		if !child.waited {
			_ = command.Process.Kill()
			<-child.done
			child.waited = true
		}
	})
	return child
}

func (child *windowsCrashChild) waitForCrashBoundary(t *testing.T, marker string) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(20 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case <-child.done:
			child.waited = true
			t.Fatalf("crash helper exited before its durable boundary (diagnostics=%d bytes)", child.output.Len())
		case <-deadline.C:
			t.Fatal("crash helper did not reach its durable boundary")
		case <-ticker.C:
			data, err := os.ReadFile(marker)
			if err == nil && string(data) == "ready" {
				return
			}
		}
	}
}

func (child *windowsCrashChild) kill(t *testing.T) {
	t.Helper()
	if err := child.command.Process.Kill(); err != nil {
		t.Fatal("cannot terminate crash test process")
	}
	if err := <-child.done; err == nil {
		t.Fatal("crash test process exited successfully after termination")
	}
	child.waited = true
	child.cancel()
}

func crashWindowsFixture(t *testing.T, fixture windowsCrashFixture, mode string) {
	t.Helper()
	child := startWindowsCrashChild(t, fixture, mode)
	child.waitForCrashBoundary(t, filepath.Join(fixture.control, mode+".ready"))
	child.kill(t)
}

func retryWindowsFixture(t *testing.T, fixture windowsCrashFixture) {
	t.Helper()
	child := startWindowsCrashChild(t, fixture, "retry")
	if err := <-child.done; err != nil {
		child.waited = true
		t.Fatalf("fresh process could not recover and redact (diagnostics=%d bytes)", child.output.Len())
	}
	child.waited = true
	child.cancel()
	assertWindowsCrashFixtureRedacted(t, fixture)
}

func assertWindowsCrashFixtureRedacted(t *testing.T, fixture windowsCrashFixture) {
	t.Helper()
	for i, path := range fixture.paths {
		want := bytes.ReplaceAll(fixture.originals[i], []byte(fixture.secret), []byte(redaction.Marker))
		assertSource(t, path, string(want))
		file, err := os.Open(path)
		if err != nil {
			t.Fatal("cannot inspect recovered source")
		}
		info, statErr := file.Stat()
		same := sameSecurity(file, fixture.security[i])
		_ = file.Close()
		if statErr != nil || !os.SameFile(fixture.info[i], info) || !same {
			t.Fatal("recovery changed source identity or security metadata")
		}
		assertSource(t, path+":retained-metadata", "preserved stream metadata")
		for _, stream := range []string{windowsRecoveryDataStream, windowsRecoveryReadyStream} {
			if _, err := os.Stat(path + stream); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("successful recovery retained a private journal")
			}
		}
	}
	assertNoStagedFiles(t, fixture.dir)
}

func assertWindowsCrashTornSource(t *testing.T, fixture windowsCrashFixture) {
	t.Helper()
	data, err := os.ReadFile(fixture.paths[1])
	want := bytes.ReplaceAll(fixture.originals[1], []byte(fixture.secret), []byte(redaction.Marker))
	if err != nil || bytes.Equal(data, fixture.originals[1]) || bytes.Equal(data, want) {
		t.Fatal("test did not produce a durable interrupted source write")
	}
}

func TestWindowsProcessKillDuringWriteRecoversBatch(t *testing.T) {
	for _, mode := range []string{"commit-partial", "commit-complete"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newWindowsCrashFixture(t, false)
			crashWindowsFixture(t, fixture, mode)
			first := bytes.ReplaceAll(fixture.originals[0], []byte(fixture.secret), []byte(redaction.Marker))
			assertSource(t, fixture.paths[0], string(first))
			if mode == "commit-partial" {
				assertWindowsCrashTornSource(t, fixture)
			} else {
				second := bytes.ReplaceAll(fixture.originals[1], []byte(fixture.secret), []byte(redaction.Marker))
				assertSource(t, fixture.paths[1], string(second))
			}
			retryWindowsFixture(t, fixture)
		})
	}
}

func TestWindowsInterruptedRecoveryCanResume(t *testing.T) {
	fixture := newWindowsCrashFixture(t, false)
	crashWindowsFixture(t, fixture, "commit-partial")
	assertWindowsCrashTornSource(t, fixture)
	crashWindowsFixture(t, fixture, "recover-partial")
	assertSource(t, fixture.paths[0], string(fixture.originals[0]))
	assertWindowsCrashTornSource(t, fixture)
	retryWindowsFixture(t, fixture)
}

func TestWindowsActiveTransactionCannotBeRecovered(t *testing.T) {
	fixture := newWindowsCrashFixture(t, false)
	child := startWindowsCrashChild(t, fixture, "commit-partial")
	child.waitForCrashBoundary(t, filepath.Join(fixture.control, "commit-partial.ready"))
	assertWindowsRecoveryRejected(t, fixture)
	child.kill(t)
	retryWindowsFixture(t, fixture)
}

func TestWindowsInterruptedJournalCleanupKeepsCompletedTarget(t *testing.T) {
	fixture := newWindowsCrashFixture(t, false)
	crashWindowsFixture(t, fixture, "cleanup-partial")
	path := fixture.paths[1]
	want := bytes.ReplaceAll(fixture.originals[1], []byte(fixture.secret), []byte(redaction.Marker))
	assertSource(t, path, string(want))
	root, err := openSourceRoot(fixture.paths)
	if err != nil {
		t.Fatal("cannot pin disarmed recovery fixture")
	}
	defer root.Close()
	relative, err := filepath.Rel(root.Name(), path)
	if err != nil {
		t.Fatal("cannot resolve disarmed recovery fixture")
	}
	writes := 0
	rewrite := func(*os.File, []byte) error {
		writes++
		return errors.New("completed target must not be undone")
	}
	if recovered, err := recoverWindowsSource(root, relative, 1<<20, rewrite); err != nil || !recovered || writes != 0 {
		t.Fatal("disarmed completed journal did not clean up without restoring secrets")
	}
	assertSource(t, path, string(want))
	for _, stream := range []string{windowsRecoveryDataStream, windowsRecoveryReadyStream} {
		if _, err := os.Stat(path + stream); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("completed journal payload was not removed")
		}
	}
}

func TestWindowsRecoveryRejectsJournalCorruption(t *testing.T) {
	for _, change := range []string{"cipher-bitflip", "cipher-truncated", "ready-forged", "ready-truncated", "ready-oversized", "journal-swapped"} {
		t.Run(change, func(t *testing.T) {
			fixture := newWindowsCrashFixture(t, false)
			crashWindowsFixture(t, fixture, "commit-partial")
			stream := fixture.paths[1] + windowsRecoveryDataStream
			data, err := os.ReadFile(stream)
			if err != nil || len(data) < 2 {
				t.Fatal("cannot inspect crash journal")
			}
			if bytes.Contains(data, []byte(fixture.secret)) {
				t.Fatal("recovery journal exposed original source bytes")
			}
			switch change {
			case "cipher-bitflip":
				data[len(data)/2] ^= 0x40
			case "cipher-truncated":
				data = data[:len(data)/2]
			case "ready-forged":
				stream, data = fixture.paths[1]+windowsRecoveryReadyStream, []byte{2}
			case "ready-truncated":
				stream, data = fixture.paths[1]+windowsRecoveryReadyStream, nil
			case "ready-oversized":
				stream, data = fixture.paths[1]+windowsRecoveryReadyStream, bytes.Repeat([]byte{1}, 1024)
			case "journal-swapped":
				data, err = os.ReadFile(fixture.paths[0] + windowsRecoveryDataStream)
				if err != nil {
					t.Fatal("cannot read alternate source journal")
				}
			}
			if err := os.WriteFile(stream, data, 0600); err != nil {
				t.Fatal("cannot corrupt crash fixture journal")
			}
			assertWindowsRecoveryRejected(t, fixture)
		})
	}
}
func TestWindowsRecoveryRejectsReplacedSource(t *testing.T) {
	fixture := newWindowsCrashFixture(t, false)
	crashWindowsFixture(t, fixture, "commit-partial")
	path := fixture.paths[1]
	streams := make(map[string][]byte)
	for _, name := range []string{windowsRecoveryDataStream, windowsRecoveryReadyStream} {
		data, err := os.ReadFile(path + name)
		if err != nil {
			t.Fatal("cannot retain crash journal for replay test")
		}
		streams[name] = data
	}
	if err := os.Remove(path); err != nil {
		t.Fatal("cannot replace crash fixture source")
	}
	if err := os.WriteFile(path, fixture.originals[1], 0600); err != nil {
		t.Fatal("cannot create replacement source")
	}
	for name, data := range streams {
		if err := os.WriteFile(path+name, data, 0600); err != nil {
			t.Fatal("cannot replay crash fixture journal")
		}
	}
	assertWindowsRecoveryRejected(t, fixture)
}

func TestWindowsRecoveryRejectsSourcePolicyChange(t *testing.T) {
	fixture := newWindowsCrashFixture(t, false)
	crashWindowsFixture(t, fixture, "commit-partial")
	file, err := os.Open(fixture.paths[1])
	if err != nil {
		t.Fatal("cannot open source policy fixture")
	}
	err = privateStaging(file)
	_ = file.Close()
	if err != nil {
		t.Fatal("cannot change source policy fixture")
	}
	assertWindowsRecoveryRejected(t, fixture)
}

func assertWindowsRecoveryRejected(t *testing.T, fixture windowsCrashFixture) {
	t.Helper()
	path := fixture.paths[1]
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("cannot read source before rejected recovery")
	}
	root, err := openSourceRoot(fixture.paths)
	if err != nil {
		t.Fatal("cannot pin recovery rejection fixture")
	}
	defer root.Close()
	relative, err := filepath.Rel(root.Name(), path)
	if err != nil {
		t.Fatal("cannot resolve recovery rejection fixture")
	}
	if _, err := recoverWindowsSource(root, relative, 1<<20, rewriteWindowsSource); err == nil {
		t.Fatal("accepted an unsafe or active recovery journal")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("rejected recovery modified source contents")
	}
}

func TestWindowsRecoveryPrecedesSelectionFilters(t *testing.T) {
	fixture := newWindowsCrashFixture(t, false)
	crashWindowsFixture(t, fixture, "commit-partial")
	child := startWindowsCrashChild(t, fixture, "retry-filtered")
	if err := <-child.done; err != nil {
		child.waited = true
		t.Fatalf("selection filters prevented recovery (diagnostics=%d bytes)", child.output.Len())
	}
	child.waited = true
	child.cancel()
	first := bytes.ReplaceAll(fixture.originals[0], []byte(fixture.secret), []byte(redaction.Marker))
	assertSource(t, fixture.paths[0], string(first))
	assertSource(t, fixture.paths[1], string(fixture.originals[1]))
	for _, path := range fixture.paths {
		for _, stream := range []string{windowsRecoveryDataStream, windowsRecoveryReadyStream} {
			if _, err := os.Stat(path + stream); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("filtered retry retained a recovery journal")
			}
		}
	}
}

func TestWindowsRecoveryRejectsModifiedSourceContents(t *testing.T) {
	fixture := newWindowsCrashFixture(t, false)
	crashWindowsFixture(t, fixture, "commit-partial")
	path := fixture.paths[1]
	data, err := os.ReadFile(path)
	if err != nil || len(data) < 123 {
		t.Fatal("cannot inspect modified source fixture")
	}
	data[122] = 0 // Neither authenticated ASCII version contains this byte.
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal("cannot modify source fixture")
	}
	assertWindowsRecoveryRejected(t, fixture)
}

func TestWindowsRecoveryRejectsNewHardLink(t *testing.T) {
	fixture := newWindowsCrashFixture(t, false)
	crashWindowsFixture(t, fixture, "commit-partial")
	link := filepath.Join(fixture.control, "outside-alias.go")
	if err := os.Link(fixture.paths[1], link); err != nil {
		t.Fatal("cannot create required recovery hard-link fixture")
	}
	assertWindowsRecoveryRejected(t, fixture)
}
func TestWindowsFailedRollbackFlushRetainsEveryJournal(t *testing.T) {
	root, paths, staged := stageWindowsTestSources(t)
	var commits []windowsSourceCommit
	defer func() {
		for _, commit := range commits {
			if commit.journal != nil {
				commit.journal.close()
			}
			_ = commit.file.Close()
		}
	}()
	for _, pending := range staged {
		file, err := openWindowsSource(root, pending)
		if err != nil {
			t.Fatal("cannot lock rollback flush fixture")
		}
		commits = append(commits, windowsSourceCommit{file: file, staged: pending})
	}
	for i := range commits {
		journal, err := prepareWindowsRecovery(root, commits[i])
		if err != nil {
			t.Fatal("cannot prepare rollback flush journal")
		}
		commits[i].journal = journal
	}
	calls := 0
	flush := func(file *os.File) error {
		calls++
		if calls == len(commits) {
			return errors.New("synthetic durable undo failure")
		}
		return file.Sync()
	}
	if err := clearRestoredWindowsJournals(root, commits, flush); err == nil || calls != len(commits) {
		t.Fatal("failed original flush did not withhold journal cleanup")
	}
	for i, commit := range commits {
		if commit.journal.data == nil || commit.journal.ready == nil {
			t.Fatal("a journal was discarded before every original was durable")
		}
		if _, err := commit.journal.data.Stat(); err != nil {
			t.Fatal("failed flush lost its encrypted recovery payload")
		}
		if _, err := commit.journal.ready.Stat(); err != nil {
			t.Fatal("failed flush lost its recovery marker")
		}
		assertSource(t, paths[i], string(staged[i].original))
	}
	if err := clearRestoredWindowsJournals(root, commits, func(file *os.File) error { return file.Sync() }); err != nil {
		t.Fatal("durable originals could not clear their recovery journals")
	}
	for _, path := range paths {
		for _, stream := range []string{windowsRecoveryDataStream, windowsRecoveryReadyStream} {
			if _, err := os.Stat(path + stream); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("successful original flush retained a recovery journal")
			}
		}
	}
}
func TestWindowsNativeCommandRecoversInterruptedWrite(t *testing.T) {
	_ = nativeBinary(t)
	fixture := newWindowsCrashFixture(t, true)
	crashWindowsFixture(t, fixture, "commit-partial")
	assertWindowsCrashTornSource(t, fixture)
	result := nativeCommand(t, "--json", "filesystem", "--in-place", fixture.dir)
	if result.code != 0 || len(result.stderr) != 0 || !bytes.Contains(result.stdout, []byte(nativeTestSecret)) {
		t.Fatalf("native command did not recover original findings (exit=%d; stdout=%d bytes; stderr=%d bytes)", result.code, len(result.stdout), len(result.stderr))
	}
	assertNativeJSONOutput(t, result.stdout)
	assertWindowsCrashFixtureRedacted(t, fixture)
}
