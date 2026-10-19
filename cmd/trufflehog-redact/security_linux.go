//go:build linux

package main

import (
	"bytes"
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

type securityMetadata struct {
	uid, gid int
	attrs    map[string][]byte
}

func (s securityMetadata) size() int64 {
	var size int64
	for name, value := range s.attrs {
		size += int64(len(name) + len(value))
	}
	return size
}

func captureSecurity(file *os.File) (securityMetadata, error) {
	info, err := file.Stat()
	if err != nil {
		return securityMetadata{}, errors.New("cannot inspect source ownership")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return securityMetadata{}, errors.New("cannot inspect source ownership")
	}
	result := securityMetadata{uid: int(stat.Uid), gid: int(stat.Gid), attrs: make(map[string][]byte)}
	names := make([]byte, 64<<10)
	n, err := unix.Flistxattr(int(file.Fd()), names)
	if errors.Is(err, unix.ENOTSUP) {
		return result, nil
	}
	if err != nil {
		return securityMetadata{}, errors.New("cannot inspect source security attributes")
	}
	count := 0
	for _, rawName := range bytes.Split(names[:n], []byte{0}) {
		if len(rawName) == 0 {
			continue
		}
		count++
		if count > 128 {
			return securityMetadata{}, errors.New("source security attribute count exceeds limit")
		}
		name := string(rawName)
		size, err := unix.Fgetxattr(int(file.Fd()), name, nil)
		if err != nil || size > 64<<10 || size < 0 {
			return securityMetadata{}, errors.New("cannot safely inspect source security attributes")
		}
		// A nonempty buffer avoids the size-query semantics of a nil/zero-length
		// destination if an empty attribute grows between the two syscalls.
		value := make([]byte, size+1)
		n, err := unix.Fgetxattr(int(file.Fd()), name, value)
		if err != nil {
			return securityMetadata{}, errors.New("cannot inspect source security attributes")
		}
		result.attrs[name] = bytes.Clone(value[:n])
		if result.size() > 64<<10 {
			return securityMetadata{}, errors.New("source security attributes exceed limit")
		}
	}
	return result, nil
}

func sameSecurity(file *os.File, expected securityMetadata) bool {
	current, err := captureSecurity(file)
	if err != nil || current.uid != expected.uid || current.gid != expected.gid || len(current.attrs) != len(expected.attrs) {
		return false
	}
	for name, value := range expected.attrs {
		if other, ok := current.attrs[name]; !ok || !bytes.Equal(other, value) {
			return false
		}
	}
	return true
}

func privateStaging(file *os.File) error { return file.Chmod(0600) }

func applySecurity(file *os.File, expected securityMetadata) error {
	current, err := captureSecurity(file)
	if err != nil {
		return err
	}
	// Avoid unnecessary chown, which can clear capabilities and permission bits.
	if (current.uid != expected.uid || current.gid != expected.gid) && file.Chown(expected.uid, expected.gid) != nil {
		return errors.New("cannot preserve source ownership")
	}
	for name := range current.attrs {
		if _, ok := expected.attrs[name]; !ok && unix.Fremovexattr(int(file.Fd()), name) != nil {
			return errors.New("cannot preserve source security attributes")
		}
	}
	for name, value := range expected.attrs {
		if other, ok := current.attrs[name]; !ok || !bytes.Equal(other, value) {
			if unix.Fsetxattr(int(file.Fd()), name, value, 0) != nil {
				return errors.New("cannot preserve source security attributes")
			}
		}
	}
	if !sameSecurity(file, expected) {
		return errors.New("cannot preserve source security metadata")
	}
	return nil
}
