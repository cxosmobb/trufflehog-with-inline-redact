package defaults

import (
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/guru"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/tru"
)

// RedactionDetectors includes feature-gated scanners and upstream's two known
// registry omissions. Offline preprocessing must not silently skip these types.
func RedactionDetectors() []detectors.Detector {
	return initializeDetectors(append(buildDetectorList(true), &guru.Scanner{}, &tru.Scanner{}))
}
