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
	actual, err := daclString(metadata.descriptor)
	if err != nil || actual != expected.String() {
		t.Fatal("staging inherited a broader ACL than owner and LocalSystem")
	}
}

func TestWindowsSourceIdentitySecurityAndStreamsSurviveRedaction(t *testing.T) {
	dir := t.TempDir()
	path := writeSource(t, dir, "source.go", "prefix SYNTHETIC_SECRET suffix", 0600)
	// An alternate stream and a protected source ACL belong to the original
	// file object. Editing its unnamed stream must preserve both unchanged.
	stream := path + ":retained-metadata"
	const metadata = "ordinary retained metadata"
	if err := os.WriteFile(stream, []byte(metadata), 0600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := privateStaging(source); err != nil {
		t.Fatal(err)
	}
	expected, err := captureSecurity(source)
	if err != nil {
		t.Fatal(err)
	}
	before, err := source.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	scanner := sourceScannerFunc(replaceSyntheticSecret)
	for pass := 1; pass <= 2; pass++ {
		if err := redactFiles(context.Background(), scanner, []string{path}, 1024, 2048); err != nil {
			t.Fatal(err)
		}
		assertSource(t, path, "prefix REDACTED suffix")
		assertSource(t, stream, metadata)
		source, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		after, statErr := source.Stat()
		same := sameSecurity(source, expected)
		_ = source.Close()
		if statErr != nil || !os.SameFile(before, after) || !same {
			t.Fatal("redaction replaced the source object or changed source security metadata")
		}
		assertNoStagedFiles(t, dir)
	}
}

func TestWindowsRejectsSourceACLChangesDuringScanning(t *testing.T) {
	dir := t.TempDir()
	first := writeSource(t, dir, "first.go", "SYNTHETIC_SECRET first", 0600)
	second := writeSource(t, dir, "second.go", "SYNTHETIC_SECRET second", 0600)
	calls := 0
	scanner := sourceScannerFunc(func(ctx context.Context, input []byte) ([]byte, redaction.Report, error) {
		calls++
		if calls == 2 {
			source, err := os.Open(first)
			if err != nil {
				t.Fatal(err)
			}
			err = privateStaging(source)
			_ = source.Close()
			if err != nil {
				t.Fatal(err)
			}
		}
		return replaceSyntheticSecret(ctx, input)
	})
	if err := redactFiles(context.Background(), scanner, []string{first, second}, 1024, 2048); err == nil {
		t.Fatal("accepted a source ACL change during scanning")
	}
	assertSource(t, first, "SYNTHETIC_SECRET first")
	assertSource(t, second, "SYNTHETIC_SECRET second")
	assertNoStagedFiles(t, dir)
}

// Creating an explicit audit policy requires a privileged test fixture, but the
// redaction itself does not. Ordinary-user coverage below never skips.
func TestWindowsExplicitAuditSACLSurvivesRedaction(t *testing.T) {
	dir := t.TempDir()
	path := writeSource(t, dir, "source.go", "prefix SYNTHETIC_SECRET suffix", 0600)
	source, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	audit, err := securityHandle(source, windows.READ_CONTROL|windows.ACCESS_SYSTEM_SECURITY)
	_ = source.Close()
	if err != nil {
		t.Skip("creating an explicit audit fixture requires an existing enabled audit privilege")
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
	expected, err := captureDescriptor(audit, windows.BACKUP_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	before, err := audit.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := redactFiles(context.Background(), sourceScannerFunc(replaceSyntheticSecret), []string{path}, 1024, 2048); err != nil {
		t.Fatal(err)
	}
	assertSource(t, path, "prefix REDACTED suffix")
	current, err := captureDescriptor(audit, windows.BACKUP_SECURITY_INFORMATION)
	if err != nil || current.sddl != expected.sddl {
		t.Fatal("explicit audit SACL changed")
	}
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("audited source object was replaced")
	}
	assertNoStagedFiles(t, dir)
}
