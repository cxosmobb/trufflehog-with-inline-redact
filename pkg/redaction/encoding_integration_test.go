package redaction

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/feature"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

const (
	encodingSecretAlpha = "synthetic-secret-alpha"
	encodingSecretBeta  = "synthetic-secret-beta"
)

// Real detectors are covered by coverage_test.go. This detector isolates source
// provenance from regex specifics, and refuses accidental network verification.
type encodingFixtureDetector struct{}

type encodingPairedFixtureDetector struct{ encodingFixtureDetector }

func (encodingPairedFixtureDetector) FromData(_ context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	if verify {
		return nil, errors.New("encoding fixture verification must remain disabled")
	}
	if !bytes.Contains(data, []byte(encodingSecretAlpha)) || !bytes.Contains(data, []byte(encodingSecretBeta)) {
		return nil, nil
	}
	return []detectors.Result{{
		DetectorType: detector_typepb.DetectorType_Test,
		Raw:          []byte(encodingSecretAlpha),
		SecretParts:  map[string]string{"key": encodingSecretAlpha, "secret": encodingSecretBeta},
	}}, nil
}

func (encodingFixtureDetector) Keywords() []string { return []string{"synthetic-secret"} }
func (encodingFixtureDetector) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Test
}
func (encodingFixtureDetector) Description() string { return "Synthetic redaction encoding fixture" }
func (encodingFixtureDetector) FromData(_ context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	if verify {
		return nil, errors.New("encoding fixture verification must remain disabled")
	}
	var results []detectors.Result
	for _, secret := range []string{encodingSecretAlpha, encodingSecretBeta} {
		if bytes.Contains(data, []byte(secret)) {
			results = append(results, detectors.Result{DetectorType: detector_typepb.DetectorType_Test, Raw: []byte(secret), SecretParts: map[string]string{"key": secret}})
		}
	}
	return results, nil
}

func runEncodingPipeline(t *testing.T, input, expected []byte) {
	t.Helper()
	scanner, err := New([]detectors.Detector{encodingFixtureDetector{}})
	if err != nil {
		t.Fatal(err)
	}
	before := bytes.Clone(input)
	output, report, err := scanner.Redact(context.Background(), input)
	if err != nil {
		t.Fatalf("encoded redaction pipeline failed: %v", err)
	}
	if !bytes.Equal(input, before) {
		t.Fatal("encoded redaction mutated caller input")
	}
	if !bytes.Equal(output, expected) {
		t.Fatal("encoded redaction changed source outside expected secret representations")
	}
	if report.Detections == 0 || report.Replacements == 0 {
		t.Fatal("encoded redaction omitted detection/replacement accounting")
	}
	// A second pass must preserve the result without creating new findings.
	second, secondReport, err := scanner.Redact(context.Background(), output)
	if err != nil || !bytes.Equal(second, output) || secondReport.Detections != 0 || secondReport.Replacements != 0 {
		t.Fatal("encoded redaction is not idempotent")
	}
}

func TestEncodingPipelineMultipleSecretsInBase64(t *testing.T) {
	blob := "host=localhost;user=alice;token=" + encodingSecretAlpha + ";second=" + encodingSecretBeta + ";port=443"
	redacted := "host=localhost;user=alice;token=REDACTED;second=REDACTED;port=443"
	input := []byte(`const payload = "` + base64.StdEncoding.EncodeToString([]byte(blob)) + `"; const safe = "unchanged";`)
	expected := []byte(`const payload = "` + base64.StdEncoding.EncodeToString([]byte(redacted)) + `"; const safe = "unchanged";`)
	runEncodingPipeline(t, input, expected)
}

func TestEncodingPipelineMixedRepresentationsAndRepeats(t *testing.T) {
	for _, codec := range []textCodec{codecUTF16LE, codecUTF16BE} {
		t.Run(fmt.Sprint(codec), func(t *testing.T) {
			blob := "user=alice;token=" + encodingSecretAlpha + ";second=" + encodingSecretBeta + ";safe=unchanged"
			redacted := "user=alice;token=REDACTED;second=REDACTED;safe=unchanged"
			prefix := `plain="` + encodingSecretAlpha + `"; escaped="` + escapeEncodingFixture(encodingSecretBeta) + `"; blob="` + base64.StdEncoding.EncodeToString([]byte(blob)) + `"; wide="`
			expectedPrefix := `plain="REDACTED"; escaped="REDACTED"; blob="` + base64.StdEncoding.EncodeToString([]byte(redacted)) + `"; wide="`
			input := append([]byte(prefix), encodeTextReplacement([]byte(encodingSecretAlpha), codec)...)
			input = append(input, []byte(`"; safe="unchanged"`)...)
			expected := append([]byte(expectedPrefix), encodeTextReplacement([]byte("REDACTED"), codec)...)
			expected = append(expected, []byte(`"; safe="unchanged"`)...)
			runEncodingPipeline(t, input, expected)
		})
	}
}

func TestEncodingPipelineUTF16EscapesAndBase64(t *testing.T) {
	for _, codec := range []textCodec{codecUTF16LE, codecUTF16BE} {
		t.Run(fmt.Sprint(codec), func(t *testing.T) {
			blob := "user=alice;token=" + encodingSecretAlpha + ";second=" + encodingSecretBeta + ";safe=cafe"
			redacted := "user=alice;token=REDACTED;second=REDACTED;safe=cafe"
			encoded := base64.StdEncoding.EncodeToString([]byte(blob))
			text := `😀 header; plain="` + encodingSecretAlpha + `"; blob="` + escapeEncodingFixture(encoded) + `"; safe="café"`
			expectedText := `😀 header; plain="REDACTED"; blob="` + base64.StdEncoding.EncodeToString([]byte(redacted)) + `"; safe="café"`
			bom := []byte{0xff, 0xfe}
			if codec == codecUTF16BE {
				bom = []byte{0xfe, 0xff}
			}
			input := append(bytes.Clone(bom), encodeTextReplacement([]byte(text), codec)...)
			expected := append(bytes.Clone(bom), encodeTextReplacement([]byte(expectedText), codec)...)
			runEncodingPipeline(t, input, expected)
		})
	}
}

func TestEncodingPipelineUTF16WithoutBOM(t *testing.T) {
	for _, codec := range []textCodec{codecUTF16LE, codecUTF16BE} {
		t.Run(fmt.Sprint(codec), func(t *testing.T) {
			text := "key=\"" + encodingSecretAlpha + "\"; keep=1\r\nsecond=\"" + encodingSecretBeta + "\"; safe=unchanged\r\n"
			redacted := "key=\"REDACTED\"; keep=1\r\nsecond=\"REDACTED\"; safe=unchanged\r\n"
			runEncodingPipeline(t, encodeTextReplacement([]byte(text), codec), encodeTextReplacement([]byte(redacted), codec))
		})
	}
}

func TestEncodingPipelinePercentHTMLEntities(t *testing.T) {
	var encoded strings.Builder
	for _, value := range encodingSecretAlpha {
		fmt.Fprintf(&encoded, "%%26%%23x%x%%3B", value)
	}
	input := []byte(`<a href="https://example.invalid/?token=` + encoded.String() + `&amp;user=alice">keep &lt;literal&gt; text</a>`)
	expected := []byte(`<a href="https://example.invalid/?token=REDACTED&amp;user=alice">keep &lt;literal&gt; text</a>`)
	runEncodingPipeline(t, input, expected)
}

func TestEncodingPipelineRejectsUnmappableDuplicate(t *testing.T) {
	previous := feature.HTMLDecoderEnabled.Swap(true)
	t.Cleanup(func() { feature.HTMLDecoderEnabled.Store(previous) })
	// The HTML decoder joins inline text across tag boundaries. A literal
	// duplicate must not make the fragmented representation appear covered.
	input := []byte(`<div>` + encodingSecretAlpha + `</div><span>synthetic-</span><span>secret-alpha</span>`)
	scanner, err := New([]detectors.Detector{encodingFixtureDetector{}})
	if err != nil {
		t.Fatal(err)
	}
	before := bytes.Clone(input)
	output, _, err := scanner.Redact(context.Background(), input)
	if err == nil || output != nil {
		t.Fatal("accepted unmappable secret representation because a literal duplicate existed elsewhere")
	}
	if !bytes.Equal(input, before) {
		t.Fatal("unmappable secret handling mutated caller input")
	}
}

func TestEncodingPipelineRejectsUnmappablePairedComponent(t *testing.T) {
	// Masking alpha disables this detector. Beta still has to be checked
	// independently against every original sensitive component, because its
	// inline HTML representation cannot be mapped to one source interval.
	input := []byte(`<div>` + encodingSecretAlpha + " " + encodingSecretBeta + `</div><span>` + encodingSecretAlpha + `</span><span>synthetic-</span><span>secret-beta</span>`)
	scanner, err := New([]detectors.Detector{encodingPairedFixtureDetector{}})
	if err != nil {
		t.Fatal(err)
	}
	before := bytes.Clone(input)
	output, _, err := scanner.Redact(context.Background(), input)
	if err == nil || output != nil {
		t.Fatal("accepted residual paired secret after masking disabled its detector")
	}
	if !bytes.Equal(input, before) {
		t.Fatal("unmappable paired secret handling mutated caller input")
	}
}

func escapeEncodingFixture(value string) string {
	var escaped strings.Builder
	for _, character := range value {
		fmt.Fprintf(&escaped, `\u%04x`, character)
	}
	return escaped.String()
}

func TestEncodingPipelineProvenanceBudgetWithholdsOutput(t *testing.T) {
	scanner, err := New([]detectors.Detector{encodingFixtureDetector{}})
	if err != nil {
		t.Fatal(err)
	}
	input := []byte(encodingSecretAlpha + strings.Repeat(`\u00e9\u0061`, maxViewPieces/2+1))
	before := bytes.Clone(input)
	output, _, err := scanner.Redact(context.Background(), input)
	if err == nil || output != nil || !bytes.Equal(input, before) {
		t.Fatal("resource budget failure exposed output or mutated the source")
	}
}
