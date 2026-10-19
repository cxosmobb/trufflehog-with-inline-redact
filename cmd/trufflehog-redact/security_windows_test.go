//go:build windows

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/redaction"
	"golang.org/x/sys/windows"
)

func TestWindowsStageACLIsPrivateBeforeWriting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stage")
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := privateStaging(file); err != nil {
		t.Fatal(err)
	}
	metadata, err := captureDescriptor(file, accessSecurityInformation)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := metadata.descriptor.Owner()
	if err != nil {
		t.Fatal(err)
	}
	expected, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + owner.String() + ")(A;;FA;;;SY)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := metadata.descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	actual, err := windows.NewSecurityDescriptor()
	if err != nil || actual.SetDACL(dacl, true, false) != nil || actual.SetControl(windows.SE_DACL_PROTECTED, windows.SE_DACL_PROTECTED) != nil {
		t.Fatal("cannot inspect staged DACL")
	}
	if actual.String() != expected.String() {
		t.Fatalf("staging inherited a broader ACL than owner and LocalSystem: %s / %s", actual.String(), expected.String())
	}
}

func TestWindowsSourceACLAndOwnerSurviveReplacement(t *testing.T) {
	dir := t.TempDir()
	source, err := os.OpenFile(filepath.Join(dir, "source"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if err := privateStaging(source); err != nil {
		t.Fatal(err)
	}
	expected, err := captureSecurity(source)
	if err != nil {
		t.Skip("complete security descriptor requires enabled SeSecurityPrivilege")
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	stage, err := os.OpenFile(filepath.Join(dir, "stage"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	if err := privateStaging(stage); err != nil {
		t.Fatal(err)
	}
	if err := applySecurity(stage, expected); err != nil {
		t.Fatal(err)
	}
	if err := stage.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "stage"), filepath.Join(dir, "source")); err != nil {
		t.Fatal(err)
	}
	replaced, err := os.Open(filepath.Join(dir, "source"))
	if err != nil {
		t.Fatal(err)
	}
	defer replaced.Close()
	if !sameSecurity(replaced, expected) {
		t.Fatal("source security metadata was widened or ownership changed")
	}
}

func TestWindowsMissingAuditPrivilegeWithholdsOriginalSource(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "source.go")
	content := "prefix SYNTHETIC_SECRET suffix"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_, metadataErr := captureSecurity(file)
	_ = file.Close()
	if metadataErr == nil {
		t.Skip("current token has enabled audit privilege")
	}
	calls := 0
	scanner := sourceScannerFunc(func(ctx context.Context, input []byte) ([]byte, redaction.Report, error) {
		calls++
		return replaceSyntheticSecret(ctx, input)
	})
	if err := redactFiles(context.Background(), scanner, []string{path}, 1024, 2048); err == nil {
		t.Fatal("source replacement accepted without complete audit metadata")
	}
	if calls != 0 {
		t.Fatal("scanner ran after complete security metadata could not be captured")
	}
	assertSource(t, path, content)
	assertNoStagedFiles(t, dir)
}

func TestWindowsExplicitAuditSACLSurvivesReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "source")
	source, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	audit, err := securityHandle(source, windows.READ_CONTROL|windows.ACCESS_SYSTEM_SECURITY)
	if err != nil {
		t.Skip("explicit audit SACL test requires enabled SeSecurityPrivilege")
	}
	defer audit.Close()
	policy, err := windows.SecurityDescriptorFromString("S:P(AU;SAFA;FR;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	sacl, _, err := policy.SACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetSecurityInfo(windows.Handle(audit.Fd()), windows.SE_FILE_OBJECT, windows.SACL_SECURITY_INFORMATION|windows.PROTECTED_SACL_SECURITY_INFORMATION, nil, nil, nil, sacl); err != nil {
		t.Fatal("cannot create explicit audit SACL fixture")
	}
	expected, err := captureSecurity(source)
	if err != nil {
		t.Fatal(err)
	}
	stage, err := os.OpenFile(filepath.Join(dir, "stage"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	if err := privateStaging(stage); err != nil {
		t.Fatal(err)
	}
	if err := applySecurity(stage, expected); err != nil {
		t.Fatal(err)
	}
	if err := stage.Close(); err != nil {
		t.Fatal(err)
	}
	_ = audit.Close()
	_ = source.Close()
	if err := os.Rename(filepath.Join(dir, "stage"), path); err != nil {
		t.Fatal(err)
	}
	replaced, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer replaced.Close()
	if !sameSecurity(replaced, expected) {
		t.Fatal("complete security descriptor or explicit audit SACL was lost")
	}
}

func TestWindowsRootRenameMetadata(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.WriteFile("source", []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := root.OpenFile("stage", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := privateStaging(file); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("replacement")); err != nil || file.Sync() != nil || file.Close() != nil {
		t.Fatal("cannot finish stage")
	}
	file, err = root.OpenFile("stage", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	before, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if file.Chmod(0600) != nil || file.Sync() != nil || file.Close() != nil {
		t.Fatal("cannot finish permissions")
	}
	expected, err := root.Stat("stage")
	if err != nil || !os.SameFile(before, expected) {
		t.Fatal("stage identity changed on close")
	}
	if err := root.Rename("stage", "source"); err != nil {
		t.Fatal(err)
	}
	current, err := root.Stat("source")
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(expected, current) || expected.Mode() != current.Mode() || expected.Size() != current.Size() || !expected.ModTime().Equal(current.ModTime()) {
		t.Fatalf("rename changed metadata: identity=%v modes=%v/%v sizes=%d/%d times=%v/%v", os.SameFile(expected, current), expected.Mode(), current.Mode(), expected.Size(), current.Size(), expected.ModTime(), current.ModTime())
	}
}
