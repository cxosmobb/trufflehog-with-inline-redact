// Package sourceredact applies validated secret edits to original source files.
package sourceredact

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
	"github.com/trufflesecurity/trufflehog/v3/pkg/redaction"
)

// Scanner produces source edits without exposing detected credentials.
type Scanner interface {
	Redact(context.Context, []byte) ([]byte, redaction.Report, error)
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("trufflehog-redact", flag.ContinueOnError)
	flags.SetOutput(stderr)
	inPlace := flags.Bool("in-place", false, "Overwrite the named source files/directories after successful redaction")
	maxBytes := flags.Int64("max-bytes", 16<<20, "Maximum bytes per source file or stdin; exceeding the limit fails")
	maxTotal := flags.Int64("max-total-bytes", 256<<20, "Maximum total input bytes for an in-place batch")
	maxFiles := flags.Int("max-files", 10000, "Maximum number of files in an in-place batch")
	timeout := flags.Duration("timeout", 5*time.Minute, "Time budget checked during scanning and commit; input reads can block")
	flags.Usage = func() {
		fmt.Fprintln(flags.Output(), "Usage: trufflehog-redact [options] < source > redacted-source\n       trufflehog-redact --in-place [options] path [path ...]")
		flags.PrintDefaults()
	}
	// flag's parser includes rejected argument values in diagnostics. These can
	// themselves be credentials; only explicitly requested help is printable.
	flags.SetOutput(io.Discard)
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			flags.SetOutput(stderr)
			flags.Usage()
			return nil
		}
		return errors.New("invalid command options")
	}
	if *maxBytes < 1 || *maxTotal < 1 || *maxFiles < 1 || *timeout <= 0 {
		return errors.New("limits and timeout must be positive")
	}
	if *inPlace != (flags.NArg() > 0) {
		return errors.New("source paths require --in-place; stdin mode accepts no paths")
	}
	scanner, err := redaction.New(defaults.RedactionDetectors())
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	if !*inPlace {
		data, err := readLimited(stdin, *maxBytes)
		if err != nil {
			return err
		}
		if unsupportedContainer(data) {
			return errors.New("container/archive input requires extraction before redaction")
		}
		output, _, err := scanner.Redact(ctx, data)
		if err != nil {
			return err
		}
		n, err := stdout.Write(output)
		if err != nil || n != len(output) {
			return errors.New("cannot write redacted output")
		}
		return nil
	}
	paths, err := sourceFilesLimited(ctx, flags.Args(), *maxFiles)
	if err != nil {
		return err
	}
	return redactFiles(ctx, scanner, paths, *maxBytes, *maxTotal)
}

func readLimited(reader io.Reader, limit int64) ([]byte, error) {
	readLimit := limit
	if readLimit < math.MaxInt64 {
		readLimit++
	}
	data, err := io.ReadAll(io.LimitReader(reader, readLimit))
	if err != nil {
		return nil, errors.New("cannot read source input")
	}
	if int64(len(data)) > limit {
		return nil, errors.New("source input exceeds size limit")
	}
	return data, nil
}

func unsupportedContainer(data []byte) bool {
	for _, magic := range [][]byte{[]byte("PK\x03\x04"), []byte("PK\x05\x06"), {0x1f, 0x8b}, []byte("7z\xbc\xaf\x27\x1c"), []byte("Rar!"), []byte("%PDF-"), []byte("BZh"), {0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00}, {0x28, 0xb5, 0x2f, 0xfd}, []byte("!<arch>\n"), {0xed, 0xab, 0xee, 0xdb}} {
		if bytes.HasPrefix(data, magic) {
			return true
		}
	}
	return len(data) > 262 && string(data[257:262]) == "ustar"
}

func sourceFiles(inputs []string) ([]string, error) {
	return sourceFilesLimited(context.Background(), inputs, 10000)
}

func sourceFilesLimited(ctx context.Context, inputs []string, maxFiles int) ([]string, error) {
	return sourceFilesSelected(ctx, inputs, maxFiles, nil, nil, false)
}

func sourceFilesSelected(ctx context.Context, inputs []string, maxFiles int, includePath, skipDirectory func(string) bool, nativePathFilters bool) ([]string, error) {
	seen := make(map[string]string)
	directories := make(map[string]bool)
	for _, input := range inputs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		path, err := filepath.Abs(input)
		if err != nil {
			return nil, errors.New("cannot resolve source path")
		}
		if !canonicalSourcePath(path) {
			return nil, errors.New("symbolic source paths are unsupported")
		}
		err = walkSourceTree(ctx, path, func(file string, entry os.DirEntry, walkErr error) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if walkErr != nil {
				return errors.New("cannot enumerate source tree")
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return errors.New("source tree contains a symbolic link")
			}
			filterPath := file
			if nativePathFilters {
				rel, err := filepath.Rel(path, file)
				if err != nil {
					return errors.New("cannot resolve source filter path")
				}
				filterPath = filepath.Join(filepath.Clean(input), rel)
			}
			key := file
			if runtime.GOOS == "windows" {
				key = strings.ToLower(file)
			}
			if entry.IsDir() {
				if entry.Name() == ".git" {
					return filepath.SkipDir
				}
				if !directories[key] && len(directories) >= maxFiles {
					return errors.New("source tree exceeds directory count limit")
				}
				directories[key] = true
				if skipDirectory != nil && skipDirectory(filterPath) {
					return filepath.SkipDir
				}
				return nil
			}
			info, err := entry.Info()
			if err != nil || !info.Mode().IsRegular() {
				return errors.New("source tree contains an unreadable or nonregular file")
			}
			if includePath != nil && !(nativePathFilters && samePath(file, path)) && !includePath(filterPath) {
				return nil
			}
			if _, exists := seen[key]; !exists && len(seen) >= maxFiles {
				return errors.New("source batch exceeds file count limit")
			}
			seen[key] = file
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	paths := make([]string, 0, len(seen))
	for _, file := range seen {
		paths = append(paths, file)
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return nil, errors.New("no source files supplied")
	}
	return paths, nil
}

// WalkDir reads and sorts a complete directory before invoking its callback.
// Read entries in fixed batches instead, so a hostile import cannot allocate
// millions of entries before the file/directory budget is enforced.
func walkSourceTree(ctx context.Context, path string, visit fs.WalkDirFunc) error {
	info, err := os.Lstat(path)
	if err != nil {
		return visit(path, nil, err)
	}
	if err := visit(path, fs.FileInfoToDirEntry(info), nil); err != nil {
		if errors.Is(err, filepath.SkipDir) {
			return nil
		}
		return err
	}
	if !info.IsDir() {
		return nil
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return errors.New("cannot pin source tree")
	}
	defer root.Close()
	var walk func(string, int) error
	walk = func(rel string, depth int) error {
		if depth > 128 {
			return errors.New("source tree exceeds directory depth limit")
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		dir, err := root.Open(rel)
		if err != nil {
			return errors.New("cannot enumerate source tree")
		}
		defer dir.Close()
		for {
			entries, readErr := dir.ReadDir(128)
			for _, entry := range entries {
				child := filepath.Join(rel, entry.Name())
				if err := visit(filepath.Join(path, child), entry, nil); err != nil {
					if errors.Is(err, filepath.SkipDir) && entry.IsDir() {
						continue
					}
					return err
				}
				if entry.IsDir() {
					if err := walk(child, depth+1); err != nil {
						return err
					}
				}
			}
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			if readErr != nil {
				return errors.New("cannot enumerate source tree")
			}
		}
	}
	return walk(".", 0)
}

type stagedFile struct {
	path, temp               string
	original, redacted       []byte
	mode                     os.FileMode
	originalInfo, stagedInfo os.FileInfo
	security                 securityMetadata
}

// redactFiles stages every file before overwriting any original. A failed
// detector/encoding/size check therefore leaves the entire import untouched.
func redactFiles(ctx context.Context, scanner Scanner, paths []string, maxBytes, maxTotal int64) error {
	return redactFilesWithOptions(ctx, scanner, paths, maxBytes, maxTotal, nil)
}

func redactFilesWithOptions(ctx context.Context, scanner Scanner, paths []string, maxBytes, maxTotal int64, beforeCommit func(context.Context) error) error {
	root, err := openSourceRoot(paths)
	if err != nil {
		return err
	}
	defer root.Close()
	var staged []stagedFile
	defer func() {
		for _, file := range staged {
			if file.temp != "" {
				_ = root.Remove(file.temp)
			}
		}
	}()
	var total int64
	var securityTotal int64
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return err
		}
		rel, err := filepath.Rel(root.Name(), path)
		if err != nil || !filepath.IsLocal(rel) {
			return errors.New("source path escapes input root")
		}
		file, info, err := openRegularSource(root, rel, nil, os.O_RDONLY)
		if err != nil {
			return err
		}
		if info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			_ = file.Close()
			return errors.New("special source permission bits are unsupported")
		}
		security, err := captureSecurity(file)
		if err != nil || securityTotal+security.size() > 16<<20 {
			_ = file.Close()
			return errors.New("cannot safely preserve source security metadata")
		}
		securityTotal += security.size()
		limit := min(maxBytes, maxTotal-total)
		if info.Size() > limit {
			_ = file.Close()
			return errors.New("source input exceeds size limit")
		}
		data, readErr := readLimited(file, limit)
		after, statErr := file.Stat()
		closeErr := file.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return errors.New("cannot close source file")
		}
		if statErr != nil || !sameSource(info, after) {
			return errors.New("source changed during read; batch withheld")
		}
		if int64(len(data)) > maxTotal-total {
			return errors.New("source batch exceeds total size limit")
		}
		total += int64(len(data))
		if unsupportedContainer(data) {
			return errors.New("source tree contains a container/archive; extract it before redaction")
		}
		output, _, err := scanner.Redact(ctx, data)
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		pending := stagedFile{path: rel, original: data, redacted: output, mode: info.Mode(), originalInfo: info, security: security}
		if beforeCommit == nil && !bytes.Equal(data, output) {
			pending.temp, pending.stagedInfo, err = stageBytes(root, rel, output)
			if err != nil {
				return err
			}
		}
		staged = append(staged, pending)
	}
	if err := validateStagedSources(ctx, root, staged); err != nil {
		return err
	}
	if beforeCommit != nil {
		// Ordinary scanner output must see only original source files, never
		// the private redacted stages kept beside them during the commit.
		if err := beforeCommit(ctx); err != nil {
			return err
		}
		if err := validateStagedSources(ctx, root, staged); err != nil {
			return err
		}
		for i := range staged {
			if err := ctx.Err(); err != nil {
				return err
			}
			file := &staged[i]
			if bytes.Equal(file.original, file.redacted) {
				continue
			}
			file.temp, file.stagedInfo, err = stageBytes(root, file.path, file.redacted)
			if err != nil {
				return err
			}
		}
		if err := validateStagedSources(ctx, root, staged); err != nil {
			return err
		}
	}
	return commitFiles(ctx, root, staged)
}

func validateStagedSources(ctx context.Context, root *os.Root, staged []stagedFile) error {
	for _, file := range staged {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !unchangedSource(root, file.path, file.original, file.originalInfo, file.security) {
			return errors.New("source changed during redaction; batch withheld")
		}
		if file.temp != "" && !unchangedSource(root, file.temp, file.redacted, file.stagedInfo) {
			return errors.New("staged source changed during redaction; batch withheld")
		}
	}
	return nil
}

func stageBytes(root *os.Root, path string, data []byte) (string, os.FileInfo, error) {
	// Exclusive creation and private permissions protect rollback originals and
	// keep staged output immutable to other users until the final replacement.
	name := filepath.Join(filepath.Dir(path), ".trufflehog-redact-"+rand.Text())
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", nil, errors.New("cannot stage source file")
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = root.Remove(name)
		}
	}()
	if privateStaging(file) != nil {
		return "", nil, errors.New("cannot protect staged source")
	}
	if _, err = file.Write(data); err != nil {
		return "", nil, errors.New("cannot write staged source")
	}
	closedInfo, err := finishStagedFile(root, name, file)
	if err != nil {
		return "", nil, err
	}
	ok = true
	return name, closedInfo, nil
}

// A single pinned root prevents ancestor replacement from redirecting reads,
// staging or renames outside the input tree. In-place use still requires an
// exclusively owned tree: the operating system does not provide a batch-wide
// compare-and-swap transaction against malicious concurrent file writers.
func openSourceRoot(paths []string) (*os.Root, error) {
	if len(paths) == 0 {
		return nil, errors.New("no source files supplied")
	}
	dir := filepath.Dir(paths[0])
	for _, path := range paths[1:] {
		for {
			rel, err := filepath.Rel(dir, path)
			if err == nil && filepath.IsLocal(rel) {
				break
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				return nil, errors.New("source paths must share one filesystem root")
			}
			dir = parent
		}
	}
	if !canonicalSourcePath(dir) {
		return nil, errors.New("cannot pin a symbolic or unreadable input directory")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, errors.New("cannot pin input directory")
	}
	if !unchangedRoot(root) {
		_ = root.Close()
		return nil, errors.New("input directory changed during redaction")
	}
	return root, nil
}

func samePath(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
	}
	return filepath.Clean(a) == filepath.Clean(b)
}

func unchangedRoot(root *os.Root) bool {
	if !canonicalSourcePath(root.Name()) {
		return false
	}
	pinned, err := root.Stat(".")
	if err != nil {
		return false
	}
	named, err := os.Lstat(root.Name())
	return err == nil && named.IsDir() && os.SameFile(pinned, named)
}

func openRegularSource(root *os.Root, path string, expected os.FileInfo, flags int) (*os.File, os.FileInfo, error) {
	if !filepath.IsLocal(path) || !unchangedRoot(root) {
		return nil, nil, errors.New("input directory changed during redaction")
	}
	for parent := filepath.Dir(path); parent != "."; parent = filepath.Dir(parent) {
		info, err := root.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, nil, errors.New("symbolic source paths are unsupported")
		}
	}
	named, err := root.Lstat(path)
	if err != nil || !named.Mode().IsRegular() || (expected != nil && !sameSource(expected, named)) {
		return nil, nil, errors.New("source identity or metadata changed during redaction")
	}
	file, err := root.OpenFile(path, flags, 0)
	if err != nil {
		return nil, nil, errors.New("cannot open source file")
	}
	info, err := file.Stat()
	if err != nil || !sameSource(named, info) {
		_ = file.Close()
		return nil, nil, errors.New("source changed while opening; batch withheld")
	}
	return file, info, nil
}

func sameSource(a, b os.FileInfo) bool {
	return os.SameFile(a, b) && a.Mode() == b.Mode() && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

func unchangedSource(root *os.Root, path string, expected []byte, info os.FileInfo, security ...securityMetadata) bool {
	file, before, err := openRegularSource(root, path, info, os.O_RDONLY)
	if err != nil {
		return false
	}
	defer file.Close()
	if len(security) > 0 && !sameSecurity(file, security[0]) {
		return false
	}
	if before.Size() != int64(len(expected)) {
		return false
	}
	data, err := readLimited(file, int64(len(expected)))
	after, statErr := file.Stat()
	return err == nil && statErr == nil && sameSource(before, after) && bytes.Equal(data, expected)
}

// Check the open handle against the named file after durable writes and closing.
func finishStagedFile(root *os.Root, path string, file *os.File) (os.FileInfo, error) {
	if file.Sync() != nil {
		return nil, errors.New("cannot finish staged source")
	}
	info, err := file.Stat()
	if err != nil || file.Close() != nil {
		return nil, errors.New("cannot finish staged source")
	}
	closedInfo, err := root.Stat(path)
	if err != nil || !os.SameFile(info, closedInfo) {
		return nil, errors.New("staged source changed while closing")
	}
	return closedInfo, nil
}
