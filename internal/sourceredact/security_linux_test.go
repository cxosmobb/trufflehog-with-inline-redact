//go:build linux

package sourceredact

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func setTestAttribute(t *testing.T, file *os.File, name, value string) {
	t.Helper()
	if err := unix.Fsetxattr(int(file.Fd()), name, []byte(value), 0); err != nil {
		if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EPERM) {
			t.Skip("filesystem does not support user extended attributes")
		}
		t.Fatal(err)
	}
}

func TestLinuxOwnershipAndAttributesSurviveReplacement(t *testing.T) {
	dir := t.TempDir()
	source, err := os.OpenFile(filepath.Join(dir, "source"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0640)
	if err != nil {
		t.Fatal(err)
	}
	setTestAttribute(t, source, "user.redaction-fixture", "preserve this metadata")
	expected, err := captureSecurity(source)
	if err != nil {
		t.Fatal(err)
	}
	_ = source.Close()
	stage, err := os.OpenFile(filepath.Join(dir, "stage"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	setTestAttribute(t, stage, "user.unexpected-inheritance", "remove before replacing")
	if err := applySecurity(stage, expected); err != nil {
		t.Fatal(err)
	}
	if stage.Chmod(0640) != nil || stage.Close() != nil {
		t.Fatal("cannot finish staged fixture")
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
		t.Fatal("source ownership or extended attributes changed during replacement")
	}
	info, err := replaced.Stat()
	if err != nil || info.Mode().Perm() != 0640 {
		t.Fatal("source permissions changed during replacement")
	}
}

func TestLinuxDetectsAttributeChanges(t *testing.T) {
	file, err := os.OpenFile(filepath.Join(t.TempDir(), "source"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	setTestAttribute(t, file, "user.redaction-fixture", "before")
	expected, err := captureSecurity(file)
	if err != nil {
		t.Fatal(err)
	}
	setTestAttribute(t, file, "user.redaction-fixture", "after")
	if sameSecurity(file, expected) {
		t.Fatal("an external attribute change bypassed security metadata verification")
	}
}

func TestLinuxEmptyAttributeCanBeCapturedAndCopied(t *testing.T) {
	dir := t.TempDir()
	source, err := os.OpenFile(filepath.Join(dir, "source"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	setTestAttribute(t, source, "user.empty-fixture", "")
	expected, err := captureSecurity(source)
	if err != nil {
		t.Fatal(err)
	}
	stage, err := os.OpenFile(filepath.Join(dir, "stage"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	if err := applySecurity(stage, expected); err != nil || !sameSecurity(stage, expected) {
		t.Fatal("empty metadata attribute was lost")
	}
}

func TestLinuxAttributeCopyFailureIsReported(t *testing.T) {
	file, err := os.OpenFile(filepath.Join(t.TempDir(), "source"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	expected, err := captureSecurity(file)
	if err != nil {
		t.Fatal(err)
	}
	expected.attrs["invalid-attribute-without-a-namespace"] = []byte("synthetic metadata")
	if err := applySecurity(file, expected); err == nil {
		t.Fatal("a failed metadata copy was accepted")
	}
}

func TestLinuxCopiesPOSIXAccessACL(t *testing.T) {
	dir := t.TempDir()
	source, err := os.OpenFile(filepath.Join(dir, "source"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	// Linux extended POSIX ACL: version2, owner, named user65534, group, mask,
	// other. A named entry prevents the kernel optimizing it into mode bits.
	acl := []byte{2, 0, 0, 0, 1, 0, 6, 0, 255, 255, 255, 255, 2, 0, 4, 0, 254, 255, 0, 0, 4, 0, 0, 0, 255, 255, 255, 255, 16, 0, 4, 0, 255, 255, 255, 255, 32, 0, 0, 0, 255, 255, 255, 255}
	if err := unix.Fsetxattr(int(source.Fd()), "system.posix_acl_access", acl, 0); err != nil {
		if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EPERM) {
			t.Skip("filesystem does not support POSIX access ACLs")
		}
		t.Fatal(err)
	}
	expected, err := captureSecurity(source)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := expected.attrs["system.posix_acl_access"]; !ok {
		t.Fatal("fixture did not retain the extended source ACL")
	}
	stage, err := os.OpenFile(filepath.Join(dir, "stage"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	if err := applySecurity(stage, expected); err != nil || !sameSecurity(stage, expected) {
		t.Fatal("source ACL could not be preserved")
	}
}

func TestLinuxPrivateStageAndExplicitACLRestoration(t *testing.T) {
	dir := t.TempDir()
	source, err := os.OpenFile(filepath.Join(dir, "source"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	// An explicit named-user deny must survive even though other users can
	// read the original. Restoring0644 before copying this ACL would make the
	// named user readable through a different inherited stage ACL.
	denyACL := []byte{2, 0, 0, 0, 1, 0, 6, 0, 255, 255, 255, 255, 2, 0, 0, 0, 254, 255, 0, 0, 4, 0, 4, 0, 255, 255, 255, 255, 16, 0, 4, 0, 255, 255, 255, 255, 32, 0, 4, 0, 255, 255, 255, 255}
	if err := unix.Fsetxattr(int(source.Fd()), "system.posix_acl_access", denyACL, 0); err != nil {
		if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EPERM) {
			t.Skip("filesystem does not support POSIX access ACLs")
		}
		t.Fatal(err)
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
	allowACL := append([]byte(nil), denyACL...)
	allowACL[14] = 4 // Named user65534 would be readable if its mask is widened.
	if err := unix.Fsetxattr(int(stage.Fd()), "system.posix_acl_access", allowACL, 0); err != nil {
		t.Fatal(err)
	}
	if err := privateStaging(stage); err != nil {
		t.Fatal(err)
	}
	info, err := stage.Stat()
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("stage was readable outside its owner before plaintext was written")
	}
	if _, err := stage.Write([]byte("SYNTHETIC_SECRET backup")); err != nil {
		t.Fatal(err)
	}
	if err := applySecurity(stage, expected); err != nil || stage.Chmod(0644) != nil || !sameSecurity(stage, expected) {
		t.Fatal("ACL restoration or chmod widened the source's explicit named-user deny")
	}
}
