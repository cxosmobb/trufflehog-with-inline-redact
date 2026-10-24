package sourceredact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

const (
	wrongSecretsRevision = "1b51b6fbcaaba5fd69389d551d2f41ec922a4135"
	wrongSecretsDigest   = "b703b6a722db74ae007746f022bf90f5f7825e8f6cee33bd60e27ddbc206d7c5"
)

type wrongSecretsFile struct {
	hash [32]byte
	info os.FileInfo
}

func TestWrongSecretsRepositoryInPlace(t *testing.T) {
	fixture, revision := os.Getenv("REDACTION_WRONGSECRETS_FIXTURE"), os.Getenv("REDACTION_WRONGSECRETS_REVISION")
	if fixture == "" && revision == "" {
		t.Skip("pinned offline WrongSecrets fixture was not supplied")
	}
	if fixture == "" || revision != wrongSecretsRevision || os.Getenv("REDACTION_TEST_MAIN_BINARY") == "" {
		t.Fatal("WrongSecrets coverage requires its pinned fixture revision and full native executable")
	}
	dir := filepath.Join(t.TempDir(), "input")
	original := wrongSecretsSnapshot(t, fixture, dir)
	var total int64
	for _, file := range original {
		total += file.info.Size()
	}
	if len(original) != 969 || total != 225524378 || wrongSecretsManifestDigest(original) != wrongSecretsDigest {
		t.Fatal("WrongSecrets fixture does not contain the complete pinned working tree")
	}
	before := wrongSecretsCommand(t, dir, false, 183)
	if len(before.counts) == 0 || wrongSecretsChanges(t, original, wrongSecretsSnapshot(t, dir, ""), true) != 0 {
		t.Fatal("ordinary WrongSecrets scan omitted findings or changed original inputs")
	}
	printed := wrongSecretsCommand(t, dir, true, 0)
	if !reflect.DeepEqual(before.counts, printed.counts) {
		wrongSecretsFindingDifference(t, before, printed)
		t.Fatal("in-place output did not preserve the original native findings")
	}
	redacted := wrongSecretsSnapshot(t, dir, "")
	if publicHTML, exists := original["chatgpt_dump.html"]; !exists || redacted["chatgpt_dump.html"].hash != publicHTML.hash {
		t.Fatal("source redaction changed public HTML nonces or script data")
	}
	changed := wrongSecretsChanges(t, original, redacted, runtime.GOOS == "windows")
	if changed == 0 || len(wrongSecretsCommand(t, dir, false, 0).counts) != 0 {
		t.Fatal("WrongSecrets was not edited or retained native findings after redaction")
	}
	if len(wrongSecretsCommand(t, dir, true, 0).counts) != 0 || wrongSecretsChanges(t, redacted, wrongSecretsSnapshot(t, dir, ""), true) != 0 {
		t.Fatal("a second WrongSecrets redaction was not byte-for-byte idempotent")
	}
	assertNoStagedFiles(t, dir)
	t.Logf("WrongSecrets %s: %d files, %d original bytes, %d finding identities, %d changed files; zero residual findings and unchanged second pass", revision, len(original), total, len(before.counts), changed)
}

// Copy every regular working-tree file, retaining a private complete manifest.
// The fixture is acquired separately; this test never uses the network.
func wrongSecretsSnapshot(t *testing.T, root, copyTo string) map[string]wrongSecretsFile {
	t.Helper()
	manifest := make(map[string]wrongSecretsFile)
	var total int64
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Name() == ".git" {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || len(manifest) >= 969 || info.Size() > 64<<20 || info.Size() > (256<<20)-total {
			return errors.New("invalid or excessive WrongSecrets fixture file")
		}
		data, err := os.ReadFile(path)
		if err != nil || int64(len(data)) != info.Size() {
			return errors.New("cannot read complete WrongSecrets fixture file")
		}
		relative, err := filepath.Rel(root, path)
		if err != nil || !filepath.IsLocal(relative) {
			return errors.New("invalid WrongSecrets fixture path")
		}
		if copyTo != "" {
			path = filepath.Join(copyTo, relative)
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				return err
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				return err
			}
		}
		// Handle.Stat caches Windows file IDs now; pathname stats can load them
		// lazily after replacement and falsely make os.SameFile pass later.
		handle, err := os.Open(path)
		if err != nil {
			return err
		}
		info, statErr := handle.Stat()
		closeErr := handle.Close()
		if statErr != nil || closeErr != nil || !info.Mode().IsRegular() || info.Size() != int64(len(data)) {
			return errors.New("cannot capture stable WrongSecrets file identity")
		}
		if runtime.GOOS == "windows" {
			for _, stream := range []string{":trufflehog-redact-recovery-v1", ":trufflehog-redact-recovery-ready-v1"} {
				if _, err := os.Stat(path + stream); !errors.Is(err, os.ErrNotExist) {
					return errors.New("WrongSecrets retained a recovery stream")
				}
			}
		}
		total += int64(len(data))
		manifest[relative] = wrongSecretsFile{hash: sha256.Sum256(data), info: info}
		return nil
	})
	if err != nil || len(manifest) != 969 {
		t.Fatal("cannot inventory the complete private WrongSecrets tree")
	}
	return manifest
}

// Pin all contents, not just file counts and lengths. Frame sorted slash paths,
// decimal sizes and lowercase SHA256 hashes with NUL/NUL/LF using UTF-8.
func wrongSecretsManifestDigest(manifest map[string]wrongSecretsFile) string {
	names := make([]string, 0, len(manifest))
	for name := range manifest {
		names = append(names, filepath.ToSlash(name))
	}
	sort.Strings(names)
	digest := sha256.New()
	for _, name := range names {
		file := manifest[filepath.FromSlash(name)]
		_, _ = fmt.Fprintf(digest, "%s\x00%d\x00%x\n", name, file.info.Size(), file.hash)
	}
	return fmt.Sprintf("%x", digest.Sum(nil))
}

func wrongSecretsChanges(t *testing.T, before, after map[string]wrongSecretsFile, identity bool) int {
	t.Helper()
	if len(before) != len(after) {
		t.Fatal("WrongSecrets file inventory changed")
	}
	changed := 0
	for name, file := range before {
		current, exists := after[name]
		if !exists || identity && !os.SameFile(file.info, current.info) {
			t.Fatal("WrongSecrets lost a source file or replaced a retained file object")
		}
		if file.hash != current.hash {
			changed++
		}
	}
	return changed
}

// Keep secret-bearing output in memory; assertions expose only status/counts.
type wrongSecretsFinding struct {
	DetectorName, DecoderName, Raw, RawV2 string
	DetectorType                          int
	SourceMetadata                        map[string]any
}

// Native deduplication excludes decoder labels: PLAIN and BASE64 can race to
// print the same occurrence. Retain every credential and location field used
// by that deduplication, canonicalizing only JSON object property order.
func (finding wrongSecretsFinding) identity() [32]byte {
	key, _ := json.Marshal([]any{finding.DetectorName, finding.DetectorType, finding.Raw, finding.RawV2, finding.SourceMetadata})
	return sha256.Sum256(key)
}

type wrongSecretsFindingProof struct {
	detector             string
	raw, rawV2, metadata [32]byte
	decoders             map[string]int
}

type wrongSecretsFindings struct {
	counts map[[32]byte]int
	proofs map[[32]byte]wrongSecretsFindingProof
}

// Diagnostics never print original findings, filenames or credential values.
func wrongSecretsFindingDifference(t *testing.T, before, after wrongSecretsFindings) {
	t.Helper()
	keys := make(map[[32]byte]struct{})
	for key := range before.counts {
		keys[key] = struct{}{}
	}
	for key := range after.counts {
		keys[key] = struct{}{}
	}
	reported := 0
	for key := range keys {
		if before.counts[key] == after.counts[key] {
			continue
		}
		left, right := before.proofs[key], after.proofs[key]
		proof := left
		if proof.detector == "" {
			proof = right
		}
		t.Logf("native finding mismatch: detector=%s identity_sha256=%x raw_sha256=%x rawv2_sha256=%x metadata_sha256=%x before=%d inline=%d before_decoders=%v inline_decoders=%v", proof.detector, key, proof.raw, proof.rawV2, proof.metadata, before.counts[key], after.counts[key], left.decoders, right.decoders)
		reported++
		if reported == 16 {
			break
		}
	}
}

func wrongSecretsCommand(t *testing.T, dir string, inPlace bool, wantExit int) wrongSecretsFindings {
	t.Helper()
	args := []string{"--no-update", "--no-verification", "--json", "--concurrency=2", "--fail-on-scan-errors"}
	if inPlace {
		args = append(args, "--redaction-max-bytes=67108864", "--redaction-timeout=15m")
	} else {
		args = append(args, "--fail")
	}
	args = append(args, "filesystem")
	if inPlace {
		args = append(args, "--in-place")
	}
	args = append(args, dir)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, os.Getenv("REDACTION_TEST_MAIN_BINARY"), args...)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	runErr := command.Run()
	code := 0
	if runErr != nil {
		var exit *exec.ExitError
		if !errors.As(runErr, &exit) {
			t.Fatal("cannot launch native WrongSecrets scan")
		}
		code = exit.ExitCode()
	}
	if ctx.Err() != nil || code != wantExit {
		t.Fatalf("WrongSecrets native scan failed (exit=%d, expected=%d; stdout=%d bytes, stderr=%d bytes)", code, wantExit, stdout.Len(), stderr.Len())
	}
	wrongSecretsScanMetrics(t, stderr.Bytes())
	findings := wrongSecretsFindings{counts: make(map[[32]byte]int), proofs: make(map[[32]byte]wrongSecretsFindingProof)}
	decoder := json.NewDecoder(&stdout)
	for {
		var finding wrongSecretsFinding
		err := decoder.Decode(&finding)
		if errors.Is(err, io.EOF) {
			break
		}
		metadata, _ := json.Marshal(finding.SourceMetadata)
		var location struct {
			Data struct{ Filesystem struct{ File string } }
		}
		if err != nil || finding.DetectorName == "" || finding.DecoderName == "" || json.Unmarshal(metadata, &location) != nil || location.Data.Filesystem.File == "" {
			t.Fatal("WrongSecrets scan emitted malformed native findings")
		}
		key := finding.identity()
		findings.counts[key]++
		proof, exists := findings.proofs[key]
		if !exists {
			proof = wrongSecretsFindingProof{finding.DetectorName, sha256.Sum256([]byte(finding.Raw)), sha256.Sum256([]byte(finding.RawV2)), sha256.Sum256(metadata), make(map[string]int)}
		}
		proof.decoders[finding.DecoderName]++
		findings.proofs[key] = proof
	}
	return findings
}

func wrongSecretsScanMetrics(t *testing.T, data []byte) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(data))
	finished := 0
	for {
		var event struct {
			Level, Msg    string
			Bytes, Chunks int64
			Error         json.RawMessage
		}
		err := decoder.Decode(&event)
		if errors.Is(err, io.EOF) {
			break
		}
		msg := strings.ToLower(event.Msg)
		if err != nil || event.Level == "" || event.Msg == "" || event.Level == "error" || strings.Contains(msg, "error scanning") || strings.Contains(msg, "failed to") || strings.Contains(msg, "unable to") || len(event.Error) > 0 && string(event.Error) != "null" && string(event.Error) != `""` {
			t.Fatal("WrongSecrets scan emitted invalid logs or source/handler errors")
		}
		if event.Msg == "finished scanning" {
			if event.Bytes <= 0 || event.Chunks <= 0 {
				t.Fatal("WrongSecrets scan did not process source bytes and chunks")
			}
			finished++
		}
	}
	if finished != 1 {
		t.Fatal("WrongSecrets scan did not complete exactly once")
	}
}

func TestWrongSecretsFindingIdentityKeepsCredentialsAndLocations(t *testing.T) {
	fixture := []byte(`{"DetectorName":"Github","DetectorType":9,"DecoderName":"PLAIN","Raw":"synthetic-original","RawV2":"synthetic-id:synthetic-original","SourceMetadata":{"Data":{"Filesystem":{"file":"input.go","line":1}}}}`)
	var original wrongSecretsFinding
	if err := json.Unmarshal(fixture, &original); err != nil {
		t.Fatal("invalid synthetic identity fixture")
	}
	for _, test := range []struct {
		name string
		same bool
		edit func(*wrongSecretsFinding)
	}{
		{"decoder-winner", true, func(f *wrongSecretsFinding) { f.DecoderName = "BASE64" }},
		{"raw-secret", false, func(f *wrongSecretsFinding) { f.Raw = "synthetic-other" }},
		{"multipart-secret", false, func(f *wrongSecretsFinding) { f.RawV2 = "synthetic-id:synthetic-other" }},
		{"detector-name", false, func(f *wrongSecretsFinding) { f.DetectorName = "Other" }},
		{"detector-type", false, func(f *wrongSecretsFinding) { f.DetectorType++ }},
		{"source-path", false, func(f *wrongSecretsFinding) {
			f.SourceMetadata["Data"].(map[string]any)["Filesystem"].(map[string]any)["file"] = "other.go"
		}},
		{"source-line", false, func(f *wrongSecretsFinding) {
			f.SourceMetadata["Data"].(map[string]any)["Filesystem"].(map[string]any)["line"] = 2
		}},
		{"other-metadata", false, func(f *wrongSecretsFinding) { f.SourceMetadata["extra"] = "changed" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var changed wrongSecretsFinding
			if err := json.Unmarshal(fixture, &changed); err != nil {
				t.Fatal("invalid synthetic identity fixture")
			}
			test.edit(&changed)
			if (original.identity() == changed.identity()) != test.same {
				t.Fatal("native deduplication identity lost a credential/location or retained a decoder race")
			}
		})
	}
}
