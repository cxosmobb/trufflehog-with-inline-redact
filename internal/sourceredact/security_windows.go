//go:build windows

package sourceredact

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

const accessSecurityInformation = windows.OWNER_SECURITY_INFORMATION | windows.GROUP_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION | windows.LABEL_SECURITY_INFORMATION

type securityMetadata struct {
	descriptor *windows.SECURITY_DESCRIPTOR
	sddl       string
}

func (s securityMetadata) size() int64 { return int64(len(s.sddl)) }

// Only inspect the metadata readable with ordinary file access. Windows commits
// change the existing file's data, leaving its complete security descriptor,
// including the privileged audit SACL, attached to the same object throughout.
func captureSecurity(file *os.File) (securityMetadata, error) {
	return captureDescriptor(file, accessSecurityInformation)
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
