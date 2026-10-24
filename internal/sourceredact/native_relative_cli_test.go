package sourceredact

import (
	"strings"
	"testing"
)

func TestNativeInPlaceRelativePathFiltersKeepSelection(t *testing.T) {
	nativeBinary(t)
	requireInPlaceSecurity(t)
	for _, test := range []struct {
		name, flag, rule string
	}{
		{"excluded-directory", "--exclude-paths", `^src[\\/]excluded$`},
		{"included-file", "--include-paths", `^src[\\/]included\.go$`},
		{"native-byte-escape", "--include-paths", `^\Crc[\\/]included\.go$`},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			included := writeSource(t, dir, "src/included.go", nativeTestSource, 0600)
			excluded := writeSource(t, dir, "src/excluded/nested.go", nativeTestSource, 0600)
			rules := writeSource(t, t.TempDir(), "paths.txt", test.rule+"\n", 0600)
			result := nativeCommandAt(t, dir, "--json", "--include-detectors=Github", "filesystem", "--in-place", test.flag, rules, "src")
			assertNativeFindings(t, result, 0)
			assertNativeJSONSecret(t, result)
			assertSource(t, included, strings.ReplaceAll(nativeTestSource, nativeTestSecret, "REDACTED"))
			assertSource(t, excluded, nativeTestSource)
			assertNoStagedFiles(t, dir)
		})
	}
}
