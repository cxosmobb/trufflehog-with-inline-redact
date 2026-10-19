package redaction_test

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/internal/redactiontest"
	"github.com/trufflesecurity/trufflehog/v3/pkg/redaction"
)

// The reviewed snapshot changes only after a maintainer reviews upstream
// detector changes and their source mapping. A new file, a changed detector,
// or an unclassified component therefore stops CI until that review happens.
func TestReviewedDetectorSchema(t *testing.T) {
	var schema struct {
		Keys  []string `json:"keys"`
		Files []struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"files"`
		PipelineFiles []struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"pipeline_files"`
		Dynamic []string `json:"dynamic_schema_expressions"`
	}
	manifest, err := os.ReadFile("detector-schema.json")
	if err != nil || json.Unmarshal(manifest, &schema) != nil {
		t.Fatal("cannot read reviewed detector schema")
	}
	if len(schema.Files) == 0 {
		t.Fatal("reviewed detector schema is empty")
	}
	if len(schema.Dynamic) != 0 {
		t.Fatal("detector schema contains unresolved dynamic credential components")
	}
	for _, key := range schema.Keys {
		if redaction.PartPolicy(key) == "unknown" {
			t.Errorf("unreviewed credential component: %s", key)
		}
	}
	root := filepath.Join("..", "..")
	reviewed := make(map[string]string)
	for _, file := range schema.Files {
		reviewed[file.Path] = file.SHA256
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(file.Path)))
		if err != nil {
			t.Errorf("reviewed detector removed: %s", file.Path)
			continue
		}
		if fmt.Sprintf("%x", sha256.Sum256([]byte(strings.ReplaceAll(string(data), "\r\n", "\n")))) != file.SHA256 {
			t.Errorf("detector changed since redaction review: %s", file.Path)
		}
	}
	if len(schema.PipelineFiles) == 0 {
		t.Fatal("reviewed decoder and registry snapshot is empty")
	}
	for _, file := range schema.PipelineFiles {
		reviewed[file.Path] = file.SHA256
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(file.Path)))
		if err != nil || fmt.Sprintf("%x", sha256.Sum256([]byte(strings.ReplaceAll(string(data), "\r\n", "\n")))) != file.SHA256 {
			t.Errorf("pipeline file changed since redaction review: %s", file.Path)
		}
	}
	for _, subtree := range []string{"pkg/detectors", "pkg/decoders", "pkg/engine/defaults"} {
		err = filepath.WalkDir(filepath.Join(root, filepath.FromSlash(subtree)), func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			if _, ok := reviewed[filepath.ToSlash(rel)]; !ok {
				t.Errorf("new detector requires redaction review: %s", filepath.ToSlash(rel))
			}
			return nil
		})
		if err != nil {
			t.Fatal("cannot audit detector tree")
		}
	}
}

// The command corpus consumes the same reviewed real-detector samples.
func TestEveryDefaultDetectorRedacts(t *testing.T) {
	_ = redactiontest.Fixtures(t)
}
