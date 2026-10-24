// Package redaction replaces detected credential material in original source bytes.
// It never uses display-redacted findings as replacement content.
package redaction

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"sort"
	"strings"

	ahocorasick "github.com/BobuSumisu/aho-corasick"
	"github.com/go-logr/logr"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/decoders"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

const Marker = "REDACTED"

const (
	maxSourceSpans       = 131072
	maxUniqueFindings    = 4096
	maxResultsPerCall    = 8192
	maxAuditPatternBytes = 128 << 10
	// Share the former mapping/audit allowances across the complete source,
	// including nested ZIP members. MaxInt32 also supports 32-bit builds.
	maxDetectorWorkBytes = (2 << 30) - 1
)

// Span is a half-open byte range in a detector's source input.
type Span struct{ Start, End int }
type span struct{ start, end int }
type edit struct {
	start, end  int
	replacement []byte
}
type view struct {
	data  []byte
	apply func([]span) ([]edit, error)
}

// Scanner deliberately bypasses result filtering, ignore tags and deduplication.
// Verification is disabled: expired and unverified credentials remain sensitive.
type Scanner struct{ detectors []detectors.Detector }
type Report struct{ Detections, Replacements int }

func New(ds []detectors.Detector) (*Scanner, error) {
	if len(ds) == 0 {
		return nil, errors.New("redaction requires at least one detector")
	}
	for _, d := range ds {
		if d == nil || reflect.ValueOf(d).Kind() == reflect.Ptr && reflect.ValueOf(d).IsNil() {
			return nil, errors.New("nil redaction detector")
		}
	}
	return &Scanner{detectors: append([]detectors.Detector(nil), ds...)}, nil
}

// redactText returns source bytes only after every text finding has been mapped.
// Errors contain detector names and reasons, never source bytes or credentials.
func (s *Scanner) redactText(ctx context.Context, input []byte, detectorWork *int) (output []byte, report Report, err error) {
	// A detector/decoder panic must not print its secret-bearing payload or
	// release a partial source buffer. Fatal runtime faults require isolation.
	defer func() {
		if recover() != nil {
			output = nil
			err = errors.New("redaction component failed; source withheld")
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, report, err
	}
	ctx = detectors.WithSourceRedaction(logContext.WithLogger(ctx, logr.Discard()))
	views, err := buildViews(input)
	if err != nil {
		return nil, report, errors.New("cannot map source encodings")
	}
	collected := make([][]span, len(views))
	collectedSet := make([]map[span]struct{}, len(views))
	originalSecrets := make(map[string]struct{})
	seenFindings := make(map[[32]byte]struct{})
	totalSpans := 0
	collect := func(d detectors.Detector, result detectors.Result) error {
		report.Detections++
		parts, _ := json.Marshal(result.SecretParts)
		fingerprint := sha256.Sum256(append([]byte(result.DetectorType.String()+":"), parts...))
		if _, seen := seenFindings[fingerprint]; seen {
			return nil
		}
		if len(seenFindings) >= maxUniqueFindings {
			return errors.New("unique finding limit exceeded; source withheld")
		}
		seenFindings[fingerprint] = struct{}{}
		values, err := secretValues(result)
		if err != nil {
			return fmt.Errorf("detector %s has unauditable credential components; source withheld", d.Type())
		}
		for _, secret := range values {
			if secret != Marker {
				originalSecrets[secret] = struct{}{}
				if decoded, err := url.PathUnescape(secret); err == nil && decoded != "" && decoded != secret {
					originalSecrets[decoded] = struct{}{}
				}
			}
		}
		located := false
		for i, candidate := range views {
			if err := ctx.Err(); err != nil {
				return err
			}
			spans, resolveErr := Resolve(candidate.data, []detectors.Result{result})
			if resolveErr != nil {
				continue
			}
			internal := make([]span, len(spans))
			for i, r := range spans {
				internal[i] = span{r.Start, r.End}
			}
			if _, err := candidate.apply(internal); err != nil {
				continue
			}
			if collectedSet[i] == nil {
				collectedSet[i] = make(map[span]struct{})
			}
			for _, sourceSpan := range internal {
				if _, seen := collectedSet[i][sourceSpan]; seen {
					continue
				}
				if totalSpans >= maxSourceSpans {
					return errors.New("source edit limit exceeded; source withheld")
				}
				collectedSet[i][sourceSpan] = struct{}{}
				collected[i] = append(collected[i], sourceSpan)
				totalSpans++
			}
			located = true
			// A decoded finding can also exist in other source representations.
		}
		if !located {
			return fmt.Errorf("detector %s finding cannot be mapped precisely; source withheld", d.Type())
		}
		return nil
	}
	for _, candidate := range views {
		if err := s.scanFindings(ctx, candidate.data, detectorWork, collect); err != nil {
			return nil, report, err
		}
	}
	// Lossy/new upstream decoders must not let unmappable findings escape.
	decodedViews, err := upstreamDecodedViews(ctx, input)
	if err != nil {
		return nil, report, err
	}
	for _, data := range decodedViews {
		if err := s.scanFindings(ctx, data, detectorWork, collect); err != nil {
			return nil, report, err
		}
	}
	var edits []edit
	for i, candidate := range views {
		mappedEdits, mapErr := candidate.apply(collected[i])
		if mapErr != nil {
			return nil, report, errors.New("cannot combine encoded source edits; source withheld")
		}
		edits = append(edits, mappedEdits...)
	}
	output, count, err := applyEdits(input, edits)
	if err != nil {
		return nil, report, err
	}
	report.Replacements = count
	if err := s.auditOutput(ctx, output, originalSecrets, detectorWork); err != nil {
		return nil, report, err
	}
	return output, report, nil
}

// Mapping and residual auditing share execution limits and cancellation checks.
// Each detector receives a private buffer and never verifies credentials online.
func (s *Scanner) scanFindings(ctx context.Context, data []byte, work *int, visit func(detectors.Detector, detectors.Result) error) error {
	return detectorChunks(data, func(chunk []byte) error {
		lower := strings.ToLower(string(chunk))
		for _, d := range s.detectors {
			if err := ctx.Err(); err != nil {
				return err
			}
			if !eligible(d, lower) {
				continue
			}
			if len(chunk) > maxDetectorWorkBytes-*work {
				return errors.New("detector work limit exceeded; source withheld")
			}
			*work += len(chunk)
			results, err := d.FromData(ctx, false, bytes.Clone(chunk))
			if err != nil {
				return fmt.Errorf("detector %s failed; source withheld", d.Type())
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if len(results) > maxResultsPerCall {
				return errors.New("detector result limit exceeded; source withheld")
			}
			for _, result := range results {
				if err := ctx.Err(); err != nil {
					return err
				}
				if err := visit(d, result); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func eligible(d detectors.Detector, lower string) bool {
	keywords := d.Keywords()
	if len(keywords) == 0 {
		return true
	}
	for _, keyword := range keywords {
		if strings.Contains(lower, strings.ToLower(keyword)) {
			return true
		}
	}
	return false
}

// Use upstream's bounded chunk and peek sizes instead of feeding whole files
// to multipart detectors and DOM parsers, whose work can grow combinatorially.
func detectorChunks(data []byte, visit func([]byte) error) error {
	for start := 0; start < len(data) || start == 0; start += sources.DefaultChunkSize {
		end := start + sources.TotalChunkSize
		if end > len(data) {
			end = len(data)
		}
		if err := visit(data[start:end]); err != nil {
			return err
		}
		if end == len(data) {
			break
		}
	}
	return nil
}

// Preserve the original decoder output for detector execution. HTML source is
// retained only for a lazy, independent residual-provenance proof if needed.
type decodedSourceView struct{ data, htmlSource []byte }

func upstreamDecodedViews(ctx context.Context, input []byte) ([][]byte, error) {
	decoded, err := upstreamDecodedSourceViews(ctx, input)
	var views [][]byte
	for _, candidate := range decoded {
		views = append(views, candidate.data)
	}
	return views, err
}

func upstreamDecodedSourceViews(ctx context.Context, input []byte) ([]decodedSourceView, error) {
	var views []decodedSourceView
	totalBytes := 0
	err := detectorChunks(input, func(data []byte) error {
		for _, decoder := range decoders.DefaultDecoders() {
			if err := ctx.Err(); err != nil {
				return err
			}
			chunk := &sources.Chunk{Data: bytes.Clone(data)}
			var decoded *decoders.DecodableChunk
			var htmlSource []byte
			if htmlDecoder, ok := decoder.(*decoders.HTML); ok {
				decoded = htmlDecoder.FromChunkForRedaction(chunk)
				htmlSource = data
			} else if escapedDecoder, ok := decoder.(*decoders.EscapedUnicode); ok {
				decoded = escapedDecoder.FromChunkForRedaction(chunk)
			} else {
				decoded = decoder.FromChunk(chunk)
			}
			if decoded != nil && !bytes.Equal(decoded.Data, data) {
				if len(decoded.Data) > maxAllViewBytes-totalBytes {
					return errors.New("upstream decoder view budget exceeded; source withheld")
				}
				totalBytes += len(decoded.Data)
				views = append(views, decodedSourceView{decoded.Data, htmlSource})
			}
		}
		return nil
	})
	return views, err
}

// auditOutput checks the edited source itself, including upstream's lossy views.
// A literal duplicate cannot authorize leaving an unmappable encoded copy behind.
func (s *Scanner) auditOutput(ctx context.Context, output []byte, originalSecrets map[string]struct{}, detectorWork *int) error {
	views, err := buildViews(output)
	if err != nil {
		return errors.New("cannot audit redacted source")
	}
	var dataViews [][]byte
	for _, v := range views {
		dataViews = append(dataViews, v.data)
	}
	decodedViews, err := upstreamDecodedSourceViews(ctx, output)
	if err != nil {
		return err
	}
	for _, candidate := range decodedViews {
		dataViews = append(dataViews, candidate.data)
	}
	// A single multi-pattern pass prevents the residual check from doing a
	// complete source scan separately for each known secret.
	patterns := make(map[string]struct{})
	patternBytes := 0
	for secret := range originalSecrets {
		encoded, _ := json.Marshal(secret)
		for _, pattern := range []string{secret, string(encoded[1 : len(encoded)-1])} {
			if _, seen := patterns[pattern]; seen {
				continue
			}
			if len(pattern) > maxAuditPatternBytes-patternBytes {
				return errors.New("secret audit budget exceeded; source withheld")
			}
			patterns[pattern] = struct{}{}
			patternBytes += len(pattern)
		}
	}
	builder := ahocorasick.NewTrieBuilder()
	for pattern := range patterns {
		builder.AddString(pattern)
	}
	trie := builder.Build()
	auditMatches, provenanceUnits := 0, 0
	for viewIndex, data := range dataViews {
		var units []decoders.HTMLAuditUnit
		unitsReady := false
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(patterns) > 0 {
			residual := false
			var walkErr error
			trie.Walk(data, func(end, length, _ int64) bool {
				auditMatches++
				if walkErr = ctx.Err(); walkErr != nil {
					return false
				}
				if auditMatches > maxSourceSpans {
					walkErr = errors.New("secret audit match limit exceeded; source withheld")
					return false
				}
				start, stop := int(end-length+1), int(end+1)
				if viewIndex < len(views) {
					residual = literalBoundary(data, data[start:stop], start, stop)
					return !residual
				}
				residual = true
				candidate := decodedViews[viewIndex-len(views)]
				if candidate.htmlSource == nil || literalBoundary(data, data[start:stop], start, stop) {
					return false
				}
				if !unitsReady {
					// Never alter the decoder view used by detector execution.
					// Build source-unit proof only when a known component would
					// otherwise remain inside a larger HTML identifier.
					audited, intervals, err := (&decoders.HTML{}).FromChunkForRedactionAudit(&sources.Chunk{Data: bytes.Clone(candidate.htmlSource)})
					if err != nil || audited == nil || !bytes.Equal(audited.Data, data) || len(intervals) > maxAllViewPieces-provenanceUnits {
						walkErr = errors.New("cannot prove HTML residual source boundaries; source withheld")
						return false
					}
					previous := 0
					for _, interval := range intervals {
						if interval.Start < previous || interval.End <= interval.Start || interval.End > len(data) {
							walkErr = errors.New("invalid HTML residual source boundaries; source withheld")
							return false
						}
						previous = interval.End
					}
					units, unitsReady = intervals, true
					provenanceUnits += len(units)
				}
				i := sort.Search(len(units), func(i int) bool { return units[i].End > start })
				if i < len(units) && units[i].Start <= start && stop <= units[i].End {
					unit := data[units[i].Start:units[i].End]
					residual = literalBoundary(unit, data[start:stop], start-units[i].Start, stop-units[i].Start)
				}
				return !residual
			})
			if walkErr != nil {
				return walkErr
			}
			if residual {
				return errors.New("original sensitive component remains after redaction; source withheld")
			}
		}
		if err := s.scanFindings(ctx, data, detectorWork, func(d detectors.Detector, result detectors.Result) error {
			remains, err := hasUnredactedComponent(result)
			if err != nil || remains {
				return fmt.Errorf("detector %s found residual or unauditable credential material; source withheld", d.Type())
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func applyEdits(input []byte, edits []edit) ([]byte, int, error) {
	sort.Slice(edits, func(i, j int) bool {
		if edits[i].start == edits[j].start {
			return edits[i].end < edits[j].end
		}
		return edits[i].start < edits[j].start
	})
	var merged []edit
	for _, e := range edits {
		if e.start < 0 || e.end <= e.start || e.end > len(input) {
			return nil, 0, errors.New("invalid source edit; source withheld")
		}
		if len(merged) > 0 {
			last := &merged[len(merged)-1]
			if e.start < last.end {
				if e.start == last.start && e.end == last.end && bytes.Equal(e.replacement, last.replacement) {
					continue
				}
				if bytes.Equal(e.replacement, []byte(Marker)) && bytes.Equal(last.replacement, []byte(Marker)) {
					if e.end > last.end {
						last.end = e.end
					}
					continue
				}
				return nil, 0, errors.New("conflicting encoded source edits; source withheld")
			}
		}
		merged = append(merged, e)
	}
	if compiledBinary(input) {
		for i := range merged {
			width := merged[i].end - merged[i].start
			if len(merged[i].replacement) > width {
				return nil, 0, errors.New("binary replacement exceeds its source extent; source withheld")
			}
			padded := bytes.Repeat([]byte{' '}, width)
			copy(padded, merged[i].replacement)
			merged[i].replacement = padded
		}
	}
	outputSize := int64(len(input))
	for _, e := range merged {
		outputSize += int64(len(e.replacement)) - int64(e.end-e.start)
	}
	if outputSize > maxViewBytes {
		return nil, 0, errors.New("redacted source exceeds size budget; source withheld")
	}
	output, err := applyViewEdits(input, merged)
	return output, len(merged), err
}
