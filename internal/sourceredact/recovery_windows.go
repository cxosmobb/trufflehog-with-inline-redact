//go:build windows

package sourceredact

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	windowsRecoveryDataStream  = ":trufflehog-redact-recovery-v1"
	windowsRecoveryReadyStream = ":trufflehog-redact-recovery-ready-v1"
	windowsRecoveryMaxPart     = 64 << 20
	windowsRecoveryMaxHeader   = 1 << 20
	windowsRecoveryMaxPlain    = 2*windowsRecoveryMaxPart + windowsRecoveryMaxHeader + 12
	windowsRecoveryMaxCipher   = windowsRecoveryMaxPlain + 1<<20
)

var errWindowsRecovery = errors.New("cannot safely recover interrupted source edits; recovery records retained; do not forward this batch")

type windowsRecoveryIdentity struct {
	Volume, High, Low uint32
}

type windowsRecoveryRecord struct {
	Version          int
	Path, Security   string
	Source, Parent   windowsRecoveryIdentity
	Original, Target uint64
}

type windowsRecoveryJournal struct {
	commit      windowsSourceCommit
	data, ready *os.File
}

// The authenticated undo record is flushed before arming it, and arming is
// flushed before any source write. Originals never reach disk unencrypted.
func prepareWindowsRecovery(root *os.Root, commit windowsSourceCommit) (*windowsRecoveryJournal, error) {
	if !sameWindowsSource(root, commit) || !windowsContentEquals(commit.file, commit.staged.original) {
		return nil, errWindowsRecovery
	}
	record, err := windowsRecoveryBinding(root, commit)
	if err != nil {
		return nil, err
	}
	plain, err := encodeWindowsRecovery(record, commit.staged.original, commit.staged.redacted)
	if err != nil {
		return nil, err
	}
	cipher, err := protectWindowsRecovery(plain, false)
	clear(plain)
	if err != nil {
		return nil, err
	}
	journal := &windowsRecoveryJournal{commit: commit}
	journal.data, err = openWindowsRecoveryStream(commit.file, windowsRecoveryDataStream, windows.CREATE_NEW)
	if err != nil {
		return nil, errWindowsRecovery
	}
	ok := false
	defer func() {
		if !ok {
			// Source bytes have not changed. Remove only streams this call
			// exclusively created; preexisting records are never overwritten.
			_ = journal.clear()
			journal.close()
		}
	}()
	if writeWindowsRecovery(journal.data, cipher) != nil {
		return nil, errWindowsRecovery
	}
	journal.ready, err = openWindowsRecoveryStream(commit.file, windowsRecoveryReadyStream, windows.CREATE_NEW)
	if err != nil || writeWindowsRecovery(journal.ready, []byte{1}) != nil || commit.file.Sync() != nil {
		return nil, errWindowsRecovery
	}
	ok = true
	return journal, nil
}

func (journal *windowsRecoveryJournal) close() {
	if journal.ready != nil {
		_ = journal.ready.Close()
		journal.ready = nil
	}
	if journal.data != nil {
		_ = journal.data.Close()
		journal.data = nil
	}
}

// Removing the ready marker must become durable before removing its payload.
// A crash can then leave an authentic unarmed payload, never an orphaned arm.
func (journal *windowsRecoveryJournal) clear() error {
	for _, stream := range []**os.File{&journal.ready, &journal.data} {
		if *stream == nil {
			continue
		}
		remove := byte(1)
		if windows.SetFileInformationByHandle(windows.Handle((*stream).Fd()), windows.FileDispositionInfo, &remove, 1) != nil {
			return errWindowsRecovery
		}
		closeErr := (*stream).Close()
		*stream = nil
		if closeErr != nil || journal.commit.file.Sync() != nil {
			return errWindowsRecovery
		}
	}
	return nil
}

// Recovery precedes scanning: a torn write may no longer contain a detectable
// credential. Repeated interruptions restore the same original file object.
func recoverWindowsSource(root *os.Root, relative string, maxBytes int64, rewrite func(*os.File, []byte) error) (bool, error) {
	return recoverWindowsSourceWithBudget(root, relative, maxBytes, rewrite, nil)
}

func recoverWindowsSourceWithBudget(root *os.Root, relative string, maxBytes int64, rewrite func(*os.File, []byte) error, remaining *int64) (bool, error) {
	original, info, err := openRegularSource(root, relative, nil, os.O_RDONLY)
	if err != nil {
		return false, err
	}
	defer original.Close()
	journal := &windowsRecoveryJournal{}
	defer journal.close()
	journal.data, err = openWindowsRecoveryStream(original, windowsRecoveryDataStream, windows.OPEN_EXISTING)
	if err != nil && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return false, errWindowsRecovery
	}
	journal.ready, err = openWindowsRecoveryStream(original, windowsRecoveryReadyStream, windows.OPEN_EXISTING)
	if err != nil && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return false, errWindowsRecovery
	}
	if journal.data == nil && journal.ready == nil {
		return false, nil
	}
	if journal.data == nil || maxBytes < 1 {
		return false, errWindowsRecovery
	}
	security, err := captureSecurity(original)
	if err != nil {
		return false, errWindowsRecovery
	}
	handle, _, _ := reopenWindowsFile.Call(original.Fd(), uintptr(windows.GENERIC_READ|windows.GENERIC_WRITE), uintptr(windows.FILE_SHARE_READ), 0)
	if handle == uintptr(windows.InvalidHandle) {
		return false, errWindowsRecovery
	}
	source := os.NewFile(handle, original.Name())
	defer source.Close()
	journal.commit = windowsSourceCommit{file: source, staged: stagedFile{path: relative, mode: info.Mode(), originalInfo: info, security: security}}
	if !sameWindowsSource(root, journal.commit) {
		return false, errWindowsRecovery
	}
	// The source budget is checked before allocating or asking DPAPI to
	// decrypt an imported ADS. Redaction's output independently caps at 64 MiB.
	cipherLimit := min(maxBytes, int64(windowsRecoveryMaxPart)) + windowsRecoveryMaxPart + windowsRecoveryMaxHeader + 12 + 1<<20
	cipherInfo, statErr := journal.data.Stat()
	if statErr != nil || cipherInfo.Size() < 1 || cipherInfo.Size() > cipherLimit {
		return false, errWindowsRecovery
	}
	if remaining != nil {
		if cipherInfo.Size() > *remaining {
			return false, errWindowsRecovery
		}
		*remaining -= cipherInfo.Size()
	}
	cipher, err := readLimited(journal.data, cipherLimit)
	if err != nil {
		return false, errWindowsRecovery
	}
	plain, err := protectWindowsRecovery(cipher, true)
	if err != nil {
		return false, errWindowsRecovery
	}
	defer clear(plain)
	record, before, target, err := decodeWindowsRecovery(plain, maxBytes)
	binding, bindingErr := windowsRecoveryBinding(root, journal.commit)
	if err != nil || bindingErr != nil || !samePath(record.Path, binding.Path) || record.Source != binding.Source || record.Parent != binding.Parent || record.Security != binding.Security || !sameWindowsSource(root, journal.commit) {
		return false, errWindowsRecovery
	}
	if journal.ready == nil {
		if !windowsContentEquals(source, before) && !windowsContentEquals(source, target) {
			return false, errWindowsRecovery
		}
	} else {
		armed, err := readLimited(journal.ready, 1)
		if err != nil || !bytes.Equal(armed, []byte{1}) || !windowsTornSource(source, before, target) {
			return false, errWindowsRecovery
		}
		if !sameWindowsSource(root, journal.commit) || rewrite(source, before) != nil || source.Sync() != nil || !sameWindowsSource(root, journal.commit) || !windowsContentEquals(source, before) {
			return false, errWindowsRecovery
		}
	}
	if !sameWindowsSource(root, journal.commit) || journal.clear() != nil {
		return false, errWindowsRecovery
	}
	return true, nil
}

func windowsRecoveryBinding(root *os.Root, commit windowsSourceCommit) (windowsRecoveryRecord, error) {
	parent, err := root.Open(filepath.Dir(commit.staged.path))
	if err != nil {
		return windowsRecoveryRecord{}, errWindowsRecovery
	}
	defer parent.Close()
	sourceID, sourceErr := windowsRecoveryFileID(commit.file)
	parentID, parentErr := windowsRecoveryFileID(parent)
	pathBuffer := make([]uint16, 32768)
	pathSize, pathErr := windows.GetFinalPathNameByHandle(windows.Handle(commit.file.Fd()), &pathBuffer[0], uint32(len(pathBuffer)), 0)
	if sourceErr != nil || parentErr != nil || pathErr != nil || pathSize == 0 || pathSize >= uint32(len(pathBuffer)) {
		return windowsRecoveryRecord{}, errWindowsRecovery
	}
	return windowsRecoveryRecord{Version: 1, Path: windowsDOSPath(windows.UTF16ToString(pathBuffer[:pathSize])), Source: sourceID, Parent: parentID, Security: commit.staged.security.sddl}, nil
}

func windowsRecoveryFileID(file *os.File) (windowsRecoveryIdentity, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &info); err != nil {
		return windowsRecoveryIdentity{}, errWindowsRecovery
	}
	return windowsRecoveryIdentity{info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow}, nil
}

// Open a stream relative to the pinned original file object, never by pathname.
// Disposal also uses the exact ADS handle, excluding ancestor-swap redirects.
func openWindowsRecoveryStream(source *os.File, suffix string, disposition uint32) (*os.File, error) {
	name, err := windows.NewNTUnicodeString(suffix)
	if err != nil {
		return nil, errWindowsRecovery
	}
	attributes := windows.OBJECT_ATTRIBUTES{RootDirectory: windows.Handle(source.Fd()), ObjectName: name, Attributes: windows.OBJ_CASE_INSENSITIVE}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	nativeDisposition := uint32(windows.FILE_OPEN)
	if disposition == windows.CREATE_NEW {
		nativeDisposition = windows.FILE_CREATE
	} else if disposition != windows.OPEN_EXISTING {
		return nil, errWindowsRecovery
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&handle, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.DELETE|windows.SYNCHRONIZE, &attributes, &status, nil, 0, 0, nativeDisposition, windows.FILE_WRITE_THROUGH|windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT, 0, 0)
	runtime.KeepAlive(name)
	runtime.KeepAlive(source)
	if err != nil {
		if native, ok := err.(windows.NTStatus); ok {
			return nil, native.Errno()
		}
		return nil, err
	}
	stream := os.NewFile(uintptr(handle), source.Name()+suffix)
	streamID, streamErr := windowsRecoveryFileID(stream)
	sourceID, sourceErr := windowsRecoveryFileID(source)
	if streamErr != nil || sourceErr != nil || streamID != sourceID {
		_ = stream.Close()
		return nil, errWindowsRecovery
	}
	return stream, nil
}
func writeWindowsRecovery(file *os.File, data []byte) error {
	if file == nil {
		return errWindowsRecovery
	}
	if n, err := file.Write(data); err != nil || n != len(data) || file.Sync() != nil {
		return errWindowsRecovery
	}
	return nil
}

func encodeWindowsRecovery(record windowsRecoveryRecord, original, target []byte) ([]byte, error) {
	if len(original) > windowsRecoveryMaxPart || len(target) > windowsRecoveryMaxPart {
		return nil, errWindowsRecovery
	}
	record.Original, record.Target = uint64(len(original)), uint64(len(target))
	header, err := json.Marshal(record)
	if err != nil || len(header) > windowsRecoveryMaxHeader {
		return nil, errWindowsRecovery
	}
	plain := make([]byte, 12+len(header)+len(original)+len(target))
	copy(plain, "THRWIN01")
	binary.LittleEndian.PutUint32(plain[8:12], uint32(len(header)))
	position := 12 + copy(plain[12:], header)
	position += copy(plain[position:], original)
	copy(plain[position:], target)
	return plain, nil
}

func decodeWindowsRecovery(plain []byte, maxBytes int64) (windowsRecoveryRecord, []byte, []byte, error) {
	var record windowsRecoveryRecord
	if maxBytes < 1 || len(plain) < 12 || len(plain) > windowsRecoveryMaxPlain || string(plain[:8]) != "THRWIN01" {
		return record, nil, nil, errWindowsRecovery
	}
	size := uint64(binary.LittleEndian.Uint32(plain[8:12]))
	if size > windowsRecoveryMaxHeader || 12+size > uint64(len(plain)) {
		return record, nil, nil, errWindowsRecovery
	}
	decoder := json.NewDecoder(bytes.NewReader(plain[12 : 12+size]))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&record) != nil || record.Version != 1 || record.Original > windowsRecoveryMaxPart || record.Target > windowsRecoveryMaxPart || record.Original > uint64(maxBytes) || 12+size+record.Original+record.Target != uint64(len(plain)) {
		return record, nil, nil, errWindowsRecovery
	}
	start := 12 + size
	return record, plain[start : start+record.Original], plain[start+record.Original:], nil
}

// DPAPI authenticates ciphertext and restricts decryption to the current user.
// Never use CRYPTPROTECT_LOCAL_MACHINE or allow a credential prompt.
func protectWindowsRecovery(data []byte, decrypt bool) ([]byte, error) {
	limit := windowsRecoveryMaxPlain
	if decrypt {
		limit = windowsRecoveryMaxCipher
	}
	if len(data) == 0 || len(data) > limit {
		return nil, errWindowsRecovery
	}
	input := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	var output windows.DataBlob
	var err error
	if decrypt {
		err = windows.CryptUnprotectData(&input, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output)
	} else {
		err = windows.CryptProtectData(&input, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output)
	}
	runtime.KeepAlive(data)
	if output.Data != nil {
		defer func() {
			if decrypt && uint64(output.Size) <= windowsRecoveryMaxPlain {
				clear(unsafe.Slice(output.Data, int(output.Size)))
			}
			_, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(output.Data)))
		}()
	}
	if err != nil || output.Data == nil || output.Size == 0 || uint64(output.Size) > windowsRecoveryMaxCipher || (decrypt && uint64(output.Size) > windowsRecoveryMaxPlain) {
		return nil, errWindowsRecovery
	}
	return bytes.Clone(unsafe.Slice(output.Data, int(output.Size))), nil
}

// A source write or undo write can leave blocks from either authenticated
// version. Refuse other content rather than clobbering post-crash edits.
func windowsTornSource(file *os.File, original, target []byte) bool {
	info, err := file.Stat()
	if err != nil || info.Size() < int64(min(len(original), len(target))) || info.Size() > int64(max(len(original), len(target))) {
		return false
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return false
	}
	data, err := readLimited(file, int64(max(len(original), len(target))))
	if err != nil {
		return false
	}
	for i, value := range data {
		// An interrupted extension can persist initialized zeros before its
		// data blocks. Never allow that exception in the shared original range.
		if !(i < len(original) && value == original[i]) && !(i < len(target) && value == target[i]) && !(i >= min(len(original), len(target)) && value == 0) {
			return false
		}
	}
	return true
}
