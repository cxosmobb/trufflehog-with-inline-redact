package redaction

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	github "github.com/trufflesecurity/trufflehog/v3/pkg/detectors/github/v2"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

// Synthetic: the SHA256-derived native command fixture, never a provider token.
const largeInputSecret = "ghp_732e944dd9bca8079d5304a4d30f05e15e24"

func TestLargeSourceRedactsBeyondFormerLimitAndChunkBoundary(t *testing.T) {
	scanner, err := New([]detectors.Detector{github.Scanner{}})
	if err != nil {
		t.Fatal(err)
	}
	// Dots retain exact offsets without introducing artificial base64 views.
	input := bytes.Repeat([]byte("."), (33<<20)+256)
	boundary := ((32<<20)/sources.DefaultChunkSize + 1) * sources.DefaultChunkSize
	copy(input[boundary-12:], largeInputSecret)
	copy(input[len(input)-len(largeInputSecret)-8:], largeInputSecret)
	before := sha256.Sum256(input)
	output, report, err := scanner.Redact(context.Background(), input)
	if err != nil {
		t.Fatalf("bounded large-source redaction failed: %v", err)
	}
	want := bytes.ReplaceAll(input, []byte(largeInputSecret), []byte(Marker))
	if report.Replacements != 2 || !bytes.Equal(output, want) || sha256.Sum256(input) != before {
		t.Fatal("large-source edits changed unrelated bytes, missed a secret or mutated input")
	}
	second, report, err := scanner.Redact(context.Background(), output)
	if err != nil || report.Detections != 0 || report.Replacements != 0 || !bytes.Equal(second, output) {
		t.Fatal("large-source redaction is not idempotent")
	}
}

func TestLargeUnchangedSourceRetainsEveryByte(t *testing.T) {
	scanner, err := New([]detectors.Detector{github.Scanner{}})
	if err != nil {
		t.Fatal(err)
	}
	input := bytes.Repeat([]byte("."), (33<<20)+1)
	output, report, err := scanner.Redact(context.Background(), input)
	if err != nil || report.Detections != 0 || report.Replacements != 0 || !bytes.Equal(input, output) {
		t.Fatal("a bounded large benign source was rejected or changed")
	}
}

func TestLargeSourceStillRejectsAboveFixedLimit(t *testing.T) {
	scanner, err := New([]detectors.Detector{github.Scanner{}})
	if err != nil {
		t.Fatal(err)
	}
	input := make([]byte, (64<<20)+1)
	output, report, err := scanner.Redact(context.Background(), input)
	if err == nil || output != nil || report.Detections != 0 || report.Replacements != 0 {
		t.Fatal("a source above the fixed 64 MiB bound was released")
	}
}
