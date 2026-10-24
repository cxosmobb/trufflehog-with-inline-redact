package engine

import "github.com/trufflesecurity/trufflehog/v3/pkg/detectors"

// SelectDetectors applies the CLI's include/exclude rules without changing the
// supplied detector instances. Order and duplicate configurations are retained.
func SelectDetectors(input []detectors.Detector, include, exclude string) ([]detectors.Detector, error) {
	included, excluded, err := buildDetectorSets(&Config{IncludeDetectors: include, ExcludeDetectors: exclude})
	if err != nil {
		return nil, err
	}
	selected := make([]detectors.Detector, 0, len(input))
	for _, detector := range input {
		if len(included) > 0 {
			if _, ok := getWithDetectorID(detector, included); !ok {
				continue
			}
		}
		if _, ok := getWithDetectorID(detector, excluded); ok {
			continue
		}
		selected = append(selected, detector)
	}
	return selected, nil
}
