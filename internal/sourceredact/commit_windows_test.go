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
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWindowsStandardUserRedactsInPlace(t *testing.T) {
	if testing.Short() {
		if os.Getenv("REDACTION_REQUIRE_IN_PLACE") == "1" {
			t.Fatal("required standard-user corpus cannot use short mode")
		}
		t.Skip("full standard-user detector corpus is disabled in short mode")
	}
	var original windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_ASSIGN_PRIMARY, &original); err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	admin, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	denied := windows.SIDAndAttributes{Sid: admin}
	var restricted windows.Token
	// DISABLE_MAX_PRIVILEGE removes every privilege except SeChangeNotify.
	// Administrators is deny-only, so an elevated CI runner cannot mask a
	// dependency on administrative file access. Only the child is restricted.
	createRestrictedToken := windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateRestrictedToken")
	ok, _, callErr := createRestrictedToken.Call(uintptr(original), 1, 1, uintptr(unsafe.Pointer(&denied)), 0, 0, 0, 0, uintptr(unsafe.Pointer(&restricted)))
	runtime.KeepAlive(admin)
	runtime.KeepAlive(denied)
	if ok == 0 {
		t.Fatalf("cannot create unprivileged test token: %v", callErr)
	}
	defer restricted.Close()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// CI work/temp directories can grant access through Administrators only.
	// Keep the child binaries and fixtures in a user-owned directory with an
	// explicit inheritable user ACL; never change the runner's directories.
	owned := t.TempDir()
	privateWindowsTestDirectory(t, owned)
	binary = copyWindowsTestExecutable(t, binary, filepath.Join(owned, "tests.exe"))
	production := os.Getenv("REDACTION_TEST_BINARY")
	if production != "" {
		production = copyWindowsTestExecutable(t, production, filepath.Join(owned, "trufflehog-redact.exe"))
	}
	native := os.Getenv("REDACTION_TEST_MAIN_BINARY")
	if native != "" {
		native = copyWindowsTestExecutable(t, native, filepath.Join(owned, "trufflehog.exe"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 21*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "-test.run=^TestWindowsRestrictedTokenProcess$", "-test.v", "-test.timeout=20m")
	command.Env = append(os.Environ(), "TRUFFLEHOG_REDACT_RESTRICTED_TEST=1", "TEMP="+owned, "TMP="+owned, "REDACTION_TEST_BINARY="+production, "REDACTION_TEST_MAIN_BINARY="+native)
	command.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(restricted), HideWindow: true}
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Run(); err != nil {
		t.Fatalf("standard-user test process failed: %v (diagnostics=%d bytes)", err, output.Len())
	}
	if !strings.Contains(output.String(), "restricted token redaction coverage completed") {
		t.Fatal("standard-user process did not complete required coverage")
	}
	t.Log("restricted token completed every detector, production repository corpus, exact source fixtures and Windows security regressions")
}

// The production executable is launched by this process and inherits the
// restricted primary token; thread impersonation cannot provide that proof.
func TestWindowsRestrictedTokenProcess(t *testing.T) {
	if os.Getenv("TRUFFLEHOG_REDACT_RESTRICTED_TEST") != "1" {
		return
	}
	assertWindowsStandardUserToken(t)
	for _, test := range []struct {
		name string
		run  func(*testing.T)
	}{
		{"every-detector", TestEveryDetectorRedactsInPlace},
		{"production-repository", TestCommandRedactsDetectorCorpusInPlace},
		{"exact-source", TestCommandInPlaceExactMultiFileFixtures},
		{"private-staging", TestWindowsStageACLIsPrivateBeforeWriting},
		{"source-metadata", TestWindowsSourceIdentitySecurityAndStreamsSurviveRedaction},
		{"acl-change", TestWindowsRejectsSourceACLChangesDuringScanning},
		{"read-only", TestWindowsReadOnlySourceWithholdsEntireBatch},
		{"locked-source", TestWindowsLockedSourceWithholdsEntireBatch},
		{"hard-link", TestWindowsHardLinkWithholdsEntireBatch},
		{"partial-write-rollback", TestWindowsPartialWriteRollsBackCurrentAndPriorSources},
		{"cancel-after-write", TestWindowsCancellationAfterWriteRollsBack},
		{"process-kill-recovery", TestWindowsProcessKillDuringWriteRecoversBatch},
		{"interrupted-recovery", TestWindowsInterruptedRecoveryCanResume},
		{"interrupted-journal-cleanup", TestWindowsInterruptedJournalCleanupKeepsCompletedTarget},
		{"active-transaction", TestWindowsActiveTransactionCannotBeRecovered},
		{"journal-corruption", TestWindowsRecoveryRejectsJournalCorruption},
		{"journal-source-replay", TestWindowsRecoveryRejectsReplacedSource},
		{"recovery-policy-change", TestWindowsRecoveryRejectsSourcePolicyChange},
		{"recovery-before-filters", TestWindowsRecoveryPrecedesSelectionFilters},
		{"recovery-content-change", TestWindowsRecoveryRejectsModifiedSourceContents},
		{"recovery-hard-link", TestWindowsRecoveryRejectsNewHardLink},
		{"rollback-flush-failure", TestWindowsFailedRollbackFlushRetainsEveryJournal},
		{"recovery-sparse-journal-bound", TestWindowsRecoveryBoundsRejectOversizedSparseJournalBeforeAllocation},
		{"recovery-cipher-budget", TestWindowsRecoveryBoundsRejectInsufficientCipherBudget},
		{"recovery-original-budget", TestWindowsRecoveryBoundsRejectOriginalAboveConfiguredLimit},
		{"native-crash-recovery", TestWindowsNativeCommandRecoversInterruptedWrite},
	} {
		t.Run(test.name, test.run)
	}
	if !t.Failed() {
		t.Log("restricted token redaction coverage completed")
	}
}

func assertWindowsStandardUserToken(t *testing.T) {
	t.Helper()
	token := windows.GetCurrentProcessToken()
	groups, err := token.GetTokenGroups()
	if err != nil {
		t.Fatal(err)
	}
	admin, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	for _, group := range groups.AllGroups() {
		if group.Sid.String() == admin.String() && group.Attributes&windows.SE_GROUP_ENABLED != 0 {
			t.Fatal("Administrators remains enabled in the test process")
		}
	}
	name, err := windows.UTF16PtrFromString("SeChangeNotifyPrivilege")
	if err != nil {
		t.Fatal(err)
	}
	var allowed windows.LUID
	if err := windows.LookupPrivilegeValue(nil, name, &allowed); err != nil {
		t.Fatal(err)
	}
	var size uint32
	err = windows.GetTokenInformation(token, windows.TokenPrivileges, nil, 0, &size)
	if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) || size < 4 || size > 64<<10 {
		t.Fatal("cannot size restricted token privileges")
	}
	buffer := make([]byte, size)
	if err := windows.GetTokenInformation(token, windows.TokenPrivileges, &buffer[0], size, &size); err != nil {
		t.Fatal(err)
	}
	privileges := (*windows.Tokenprivileges)(unsafe.Pointer(&buffer[0]))
	if uint64(privileges.PrivilegeCount)*uint64(unsafe.Sizeof(windows.LUIDAndAttributes{}))+4 > uint64(len(buffer)) {
		t.Fatal("invalid restricted token privilege layout")
	}
	for _, privilege := range privileges.AllPrivileges() {
		if privilege.Luid != allowed {
			t.Fatal("test process retained a privilege beyond ordinary traversal")
		}
	}
}

func TestWindowsReadOnlySourceWithholdsEntireBatch(t *testing.T) {
	dir := t.TempDir()
	first := writeSource(t, dir, "first.go", "SYNTHETIC_SECRET first", 0600)
	second := writeSource(t, dir, "second.go", "SYNTHETIC_SECRET second", 0600)
	if err := os.Chmod(second, 0400); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(second, 0600)
	if err := redactFiles(context.Background(), sourceScannerFunc(replaceSyntheticSecret), []string{first, second}, 1024, 2048); err == nil {
		t.Fatal("accepted a read-only source")
	}
	assertSource(t, first, "SYNTHETIC_SECRET first")
	assertSource(t, second, "SYNTHETIC_SECRET second")
	assertNoStagedFiles(t, dir)
}

func TestWindowsLockedSourceWithholdsEntireBatch(t *testing.T) {
	dir := t.TempDir()
	first := writeSource(t, dir, "first.go", "SYNTHETIC_SECRET first", 0600)
	second := writeSource(t, dir, "second.go", "SYNTHETIC_SECRET second", 0600)
	path, err := windows.UTF16PtrFromString(second)
	if err != nil {
		t.Fatal(err)
	}
	locked, err := windows.CreateFile(path, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(locked)
	if err := redactFiles(context.Background(), sourceScannerFunc(replaceSyntheticSecret), []string{first, second}, 1024, 2048); err == nil {
		t.Fatal("accepted a source that denies write sharing")
	}
	assertSource(t, first, "SYNTHETIC_SECRET first")
	assertSource(t, second, "SYNTHETIC_SECRET second")
	assertNoStagedFiles(t, dir)
}

func TestWindowsHardLinkWithholdsEntireBatch(t *testing.T) {
	dir := t.TempDir()
	first := writeSource(t, dir, "first.go", "SYNTHETIC_SECRET first", 0600)
	second := writeSource(t, dir, "second.go", "SYNTHETIC_SECRET second", 0600)
	link := filepath.Join(t.TempDir(), "outside.go")
	if err := os.Link(second, link); err != nil {
		t.Fatal("cannot create required NTFS hard-link fixture")
	}
	if err := redactFiles(context.Background(), sourceScannerFunc(replaceSyntheticSecret), []string{first, second}, 1024, 2048); err == nil {
		t.Fatal("redaction could modify an external hard-link alias")
	}
	assertSource(t, first, "SYNTHETIC_SECRET first")
	assertSource(t, second, "SYNTHETIC_SECRET second")
	assertSource(t, link, "SYNTHETIC_SECRET second")
	assertNoStagedFiles(t, dir)
}

func TestWindowsPartialWriteRollsBackCurrentAndPriorSources(t *testing.T) {
	root, paths, staged := stageWindowsTestSources(t)
	calls := 0
	cause := errors.New("synthetic partial write failure")
	write := func(file *os.File, data []byte) error {
		calls++
		if calls == 2 {
			if _, err := file.WriteAt(data[:3], 0); err != nil {
				t.Fatal(err)
			}
			return cause
		}
		return rewriteWindowsSource(file, data)
	}
	if err := commitWindowsFiles(context.Background(), root, staged, write); !errors.Is(err, cause) {
		t.Fatal("partial write failure was not reported")
	}
	if calls != 2 {
		t.Fatal("partial-write regression did not reach the second source")
	}
	assertWindowsOriginalSources(t, paths, staged)
}

func TestWindowsCancellationAfterWriteRollsBack(t *testing.T) {
	root, paths, staged := stageWindowsTestSources(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	write := func(file *os.File, data []byte) error {
		calls++
		if err := rewriteWindowsSource(file, data); err != nil {
			return err
		}
		if calls == len(staged) {
			cancel()
		}
		return nil
	}
	if err := commitWindowsFiles(ctx, root, staged, write); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation after the final write was accepted")
	}
	if calls != len(staged) {
		t.Fatal("cancellation regression did not reach the final source")
	}
	assertWindowsOriginalSources(t, paths, staged)
}

func privateWindowsTestDirectory(t *testing.T, path string) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	policy, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")(A;OICI;FA;;;SY)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := policy.DACL()
	if err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(name, windows.READ_CONTROL|windows.WRITE_DAC, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)
	if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
}

func copyWindowsTestExecutable(t *testing.T, from, to string) string {
	t.Helper()
	input, err := os.Open(from)
	if err != nil {
		t.Fatal("cannot open test executable")
	}
	defer input.Close()
	output, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal("cannot create owned test executable")
	}
	_, copyErr := io.Copy(output, input)
	closeErr := output.Close()
	if copyErr != nil || closeErr != nil {
		t.Fatal("cannot copy owned test executable")
	}
	return to
}

func stageWindowsTestSources(t *testing.T) (*os.Root, []string, []stagedFile) {
	t.Helper()
	dir := t.TempDir()
	paths := []string{
		writeSource(t, dir, "first.go", "SYNTHETIC_SECRET first", 0600),
		writeSource(t, dir, "second.go", "SYNTHETIC_SECRET second", 0600),
	}
	root, err := openSourceRoot(paths)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	var staged []stagedFile
	for _, path := range paths {
		name := filepath.Base(path)
		file, info, err := openRegularSource(root, name, nil, os.O_RDONLY)
		if err != nil {
			t.Fatal(err)
		}
		security, err := captureSecurity(file)
		_ = file.Close()
		if err != nil {
			t.Fatal(err)
		}
		original, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		redacted := bytes.ReplaceAll(original, []byte("SYNTHETIC_SECRET"), []byte("REDACTED"))
		temp, stagedInfo, err := stageBytes(root, name, redacted)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = root.Remove(temp) })
		staged = append(staged, stagedFile{path: name, temp: temp, original: original, redacted: redacted, mode: info.Mode(), originalInfo: info, stagedInfo: stagedInfo, security: security})
	}
	return root, paths, staged
}

func assertWindowsOriginalSources(t *testing.T, paths []string, staged []stagedFile) {
	t.Helper()
	for i, path := range paths {
		assertSource(t, path, string(staged[i].original))
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		info, statErr := file.Stat()
		same := sameSecurity(file, staged[i].security)
		_ = file.Close()
		if statErr != nil || !os.SameFile(info, staged[i].originalInfo) || !same {
			t.Fatal("rollback changed source identity or metadata")
		}
	}
}
