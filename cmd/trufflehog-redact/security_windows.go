//go:build windows

package main

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

const accessSecurityInformation = windows.OWNER_SECURITY_INFORMATION | windows.GROUP_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION | windows.LABEL_SECURITY_INFORMATION
const sourceSecurityInformation = windows.BACKUP_SECURITY_INFORMATION

type securityMetadata struct {
	descriptor *windows.SECURITY_DESCRIPTOR
	sddl       string
}

func (s securityMetadata) size() int64 { return int64(len(s.sddl)) }

func captureSecurity(file *os.File) (securityMetadata, error) {
	// Auditing policy cannot be inferred from the DACL. Refuse replacement if
	// the complete descriptor (including SACL) cannot be read and restored.
	handle, err := securityHandle(file, windows.READ_CONTROL|windows.ACCESS_SYSTEM_SECURITY)
	if err != nil {
		return securityMetadata{}, errors.New("cannot inspect complete source security metadata; Windows in-place requires enabled SeSecurityPrivilege")
	}
	defer handle.Close()
	return captureDescriptor(handle, sourceSecurityInformation)
}

func captureDescriptor(file *os.File, information windows.SECURITY_INFORMATION) (securityMetadata, error) {
	descriptor, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, information)
	if err != nil || descriptor == nil || descriptor.Length() > 64<<10 {
		return securityMetadata{}, errors.New("cannot inspect source security metadata")
	}
	sddl := descriptor.String()
	if sddl == "" {
		return securityMetadata{}, errors.New("cannot inspect source security metadata")
	}
	return securityMetadata{descriptor: descriptor, sddl: sddl}, nil
}

func sameSecurity(file *os.File, expected securityMetadata) bool {
	current, err := captureSecurity(file)
	return err == nil && expected.descriptor != nil && current.sddl == expected.sddl
}

// Go's permission bits do not restrict Windows ACLs. Secure the still-empty
// stage before writing any bytes, permitting only its owner and LocalSystem.
func privateStaging(file *os.File) error {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return errors.New("cannot inspect staging owner")
	}
	user, err := token.GetTokenUser()
	_ = token.Close()
	if err != nil || user.User.Sid == nil {
		return errors.New("cannot inspect staging owner")
	}
	private, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")(A;;FA;;;SY)")
	if err != nil {
		return errors.New("cannot protect staged source")
	}
	dacl, _, err := private.DACL()
	if err != nil {
		return errors.New("cannot protect staged source")
	}
	handle, err := securityHandle(file, windows.READ_CONTROL|windows.WRITE_DAC)
	if err != nil {
		return err
	}
	defer handle.Close()
	if windows.SetSecurityInfo(windows.Handle(handle.Fd()), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil) != nil {
		return errors.New("cannot protect staged source")
	}
	current, err := captureDescriptor(file, accessSecurityInformation)
	if err != nil {
		return err
	}
	actual, err := daclString(current.descriptor)
	if err != nil || actual != private.String() {
		return errors.New("filesystem cannot persist a private staging ACL")
	}
	return nil
}

func daclString(descriptor *windows.SECURITY_DESCRIPTOR) (string, error) {
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return "", errors.New("cannot inspect protected staging ACL")
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return "", errors.New("cannot inspect protected staging ACL")
	}
	actual, err := windows.NewSecurityDescriptor()
	if err != nil || actual.SetDACL(dacl, true, false) != nil || actual.SetControl(windows.SE_DACL_PROTECTED, control&windows.SE_DACL_PROTECTED) != nil {
		return "", errors.New("cannot inspect protected staging ACL")
	}
	return actual.String(), nil
}

func applySecurity(file *os.File, expected securityMetadata) error {
	if expected.descriptor == nil {
		return errors.New("missing source security metadata")
	}
	owner, _, ownerErr := expected.descriptor.Owner()
	group, _, groupErr := expected.descriptor.Group()
	dacl, _, daclErr := expected.descriptor.DACL()
	control, _, controlErr := expected.descriptor.Control()
	if ownerErr != nil || groupErr != nil || daclErr != nil || controlErr != nil {
		return errors.New("cannot preserve source security metadata")
	}
	// BACKUP requests the complete descriptor; explicit flags also identify
	// each pointer consumed by SetSecurityInfo, including every SACL section.
	// https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo
	info := windows.SECURITY_INFORMATION(sourceSecurityInformation | windows.OWNER_SECURITY_INFORMATION | windows.GROUP_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION | windows.SACL_SECURITY_INFORMATION | windows.LABEL_SECURITY_INFORMATION | windows.ATTRIBUTE_SECURITY_INFORMATION | windows.SCOPE_SECURITY_INFORMATION)
	if control&windows.SE_DACL_PROTECTED != 0 {
		info |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		info |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	if control&windows.SE_SACL_PROTECTED != 0 {
		info |= windows.PROTECTED_SACL_SECURITY_INFORMATION
	} else {
		info |= windows.UNPROTECTED_SACL_SECURITY_INFORMATION
	}
	sacl, _, saclErr := expected.descriptor.SACL()
	if saclErr != nil && !errors.Is(saclErr, windows.ERROR_OBJECT_NOT_FOUND) {
		return errors.New("cannot preserve source security metadata")
	}
	handle, err := securityHandle(file, windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER|windows.ACCESS_SYSTEM_SECURITY)
	if err != nil {
		return err
	}
	defer handle.Close()
	if windows.SetSecurityInfo(windows.Handle(handle.Fd()), windows.SE_FILE_OBJECT, info, owner, group, dacl, sacl) != nil || !sameSecurity(file, expected) {
		return errors.New("cannot preserve source security metadata")
	}
	return nil
}

// Open a metadata handle without following a substituted final symlink. Check
// its identity against the existing rooted file handle before changing ACLs;
// this also prevents an ancestor swap from selecting a different file.
func securityHandle(file *os.File, access uint32) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(file.Name())
	if err != nil {
		return nil, errors.New("cannot inspect staged source metadata")
	}
	handle, err := windows.CreateFile(name, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, errors.New("cannot open staged source metadata")
	}
	metadata := os.NewFile(uintptr(handle), file.Name())
	originalInfo, originalErr := file.Stat()
	metadataInfo, metadataErr := metadata.Stat()
	if originalErr != nil || metadataErr != nil || !metadataInfo.Mode().IsRegular() || !os.SameFile(originalInfo, metadataInfo) {
		_ = metadata.Close()
		return nil, errors.New("staged source changed while opening metadata")
	}
	return metadata, nil
}
