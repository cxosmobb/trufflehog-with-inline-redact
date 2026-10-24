package engine

import (
	"context"
	"reflect"
	"testing"

	trContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

type selectionDetector struct {
	typ detector_typepb.DetectorType
}

func (*selectionDetector) FromData(context.Context, bool, []byte) ([]detectors.Result, error) {
	panic("selection must not scan or verify credentials")
}
func (*selectionDetector) Keywords() []string                   { return []string{"synthetic-selection"} }
func (d *selectionDetector) Type() detector_typepb.DetectorType { return d.typ }
func (*selectionDetector) Description() string                  { return "Synthetic detector selection fixture" }

type selectionVersionedDetector struct {
	selectionDetector
	version int
}

func (d *selectionVersionedDetector) Version() int { return d.version }

func TestSelectDetectors(t *testing.T) {
	v1 := &selectionVersionedDetector{selectionDetector{detector_typepb.DetectorType_Gitlab}, 1}
	v2 := &selectionVersionedDetector{selectionDetector{detector_typepb.DetectorType_Gitlab}, 2}
	custom1 := &selectionDetector{detector_typepb.DetectorType_CustomRegex}
	custom2 := &selectionDetector{detector_typepb.DetectorType_CustomRegex}
	input := []detectors.Detector{custom1, v2, custom2, v1, v2}
	cases := []struct {
		name, include, exclude string
		want                   []detectors.Detector
		wantError              bool
	}{
		{name: "empty rules preserve every configuration", want: input},
		{name: "all preserves order and duplicates", include: "all", want: input},
		{name: "names are case insensitive", include: "gItLaB", want: []detectors.Detector{v2, v1, v2}},
		{name: "specific version", include: "Gitlab.v2", want: []detectors.Detector{v2, v2}},
		{name: "generic exclusion overrides version include", include: "Gitlab.v2", exclude: "Gitlab"},
		{name: "version exclusion keeps other versions", include: "Gitlab", exclude: "Gitlab.v2", want: []detectors.Detector{v1}},
		{name: "exclude takes precedence", include: "all", exclude: "Gitlab", want: []detectors.Detector{custom1, custom2}},
		{name: "multiple custom configurations", include: "904", want: []detectors.Detector{custom1, custom2}},
		{name: "range includes custom detector", include: "903-905", want: []detectors.Detector{custom1, custom2}},
		{name: "invalid include", include: "not-a-detector", wantError: true},
		{name: "invalid exclude", exclude: "not-a-detector", wantError: true},
		{name: "version on nonversioned type", include: "CustomRegex.v1", wantError: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := append([]detectors.Detector(nil), input...)
			selected, err := SelectDetectors(input, tc.include, tc.exclude)
			if (err != nil) != tc.wantError {
				t.Fatalf("selection error = %v, want error %v", err, tc.wantError)
			}
			if !reflect.DeepEqual(input, before) {
				t.Fatal("selection mutated the caller's slice")
			}
			if tc.wantError {
				return
			}
			if len(selected) != len(tc.want) {
				t.Fatalf("selected %d instances, want %d", len(selected), len(tc.want))
			}
			for i, detector := range selected {
				if detector != tc.want[i] {
					t.Fatalf("instance %d or order changed", i)
				}
			}
			if len(selected) > 0 {
				selected[0] = nil
				if !reflect.DeepEqual(input, before) {
					t.Fatal("selection returned the caller's backing array")
				}
			}
		})
	}
}

func TestSelectDetectorsMatchesEngine(t *testing.T) {
	input := []detectors.Detector{
		&selectionVersionedDetector{selectionDetector{detector_typepb.DetectorType_Gitlab}, 1},
		&selectionVersionedDetector{selectionDetector{detector_typepb.DetectorType_Gitlab}, 2},
		&selectionDetector{detector_typepb.DetectorType_CustomRegex},
		&selectionDetector{detector_typepb.DetectorType_CustomRegex},
	}
	for _, rules := range [][2]string{{"", ""}, {"all", "Gitlab.v1"}, {"Gitlab.v2", ""}, {"904", ""}} {
		selected, err := SelectDetectors(input, rules[0], rules[1])
		if err != nil {
			t.Fatal(err)
		}
		configured, err := NewEngine(trContext.AddLogger(t.Context()), &Config{
			Concurrency:      1,
			Detectors:        input,
			IncludeDetectors: rules[0],
			ExcludeDetectors: rules[1],
			SourceManager:    sources.NewManager(),
		})
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(configured.detectors, selected) {
			t.Fatalf("engine and shared selector disagree for include=%q exclude=%q", rules[0], rules[1])
		}
	}
}
