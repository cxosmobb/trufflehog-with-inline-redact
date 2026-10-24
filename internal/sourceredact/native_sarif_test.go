package sourceredact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Keep this runner independent of nativeCommand's implicit --json: the native
// printer selection gives JSON precedence over SARIF when both flags are set.
func nativeSARIFCommand(t *testing.T, args ...string) nativeResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	flags := []string{"--no-update", "--no-verification", "--log-level=-1", "--sarif", "--include-detectors=Github"}
	command := exec.CommandContext(ctx, nativeBinary(t), append(flags, args...)...)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	if ctx.Err() != nil {
		t.Fatal("full TruffleHog SARIF command exceeded the offline test deadline")
	}
	result := nativeResult{stdout: stdout.Bytes(), stderr: stderr.Bytes()}
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatalf("cannot start full TruffleHog SARIF command: %T", err)
		}
		result.code = exit.ExitCode()
	}
	return result
}

type nativeSARIFDocument struct {
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name  string `json:"name"`
				Rules []struct {
					ID string `json:"id"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID              string            `json:"ruleId"`
			Level               string            `json:"level"`
			PartialFingerprints map[string]string `json:"partialFingerprints"`
			Locations           []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine int `json:"startLine"`
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

func assertNativeSARIF(t *testing.T, result nativeResult, code int, path string, wantFinding bool) string {
	t.Helper()
	assertNativeStatus(t, result, code, true)
	if len(result.stderr) != 0 || bytes.Contains(result.stdout, []byte(".trufflehog-redact-")) {
		t.Fatal("native SARIF command emitted diagnostics or a private staging filename")
	}
	var document nativeSARIFDocument
	if err := json.Unmarshal(result.stdout, &document); err != nil {
		t.Fatal("native command did not produce one complete SARIF document")
	}
	if document.Version != "2.1.0" || len(document.Runs) != 1 || document.Runs[0].Tool.Driver.Name != "trufflehog" {
		t.Fatal("native command lost the SARIF version, run or tool metadata")
	}
	run := document.Runs[0]
	if !wantFinding {
		if run.Results == nil || len(run.Results) != 0 || len(run.Tool.Driver.Rules) != 0 {
			t.Fatal("native SARIF second pass did not contain an empty results array")
		}
		return ""
	}
	if len(run.Tool.Driver.Rules) != 1 || run.Tool.Driver.Rules[0].ID != "Github" || len(run.Results) != 1 {
		t.Fatal("native SARIF omitted the original Github rule or finding")
	}
	finding := run.Results[0]
	if finding.RuleID != "Github" || finding.Level != "warning" || len(finding.Locations) != 1 {
		t.Fatal("native SARIF changed the offline finding classification or location count")
	}
	location := finding.Locations[0].PhysicalLocation
	if location.ArtifactLocation.URI != path || location.Region.StartLine != 1 {
		t.Fatal("native SARIF finding no longer points to the original source location")
	}
	fingerprint := finding.PartialFingerprints["trufflehogFingerprint/v1"]
	// SARIF intentionally omits raw credentials. Its fingerprint must still
	// describe the original finding, even though the file has now been edited.
	key := fmt.Sprintf("Github:%s:1:%x", path, sha256.Sum256([]byte(nativeTestSecret)))
	want := sha256.Sum256([]byte(key))
	if fingerprint != hex.EncodeToString(want[:]) {
		t.Fatal("native SARIF fingerprint does not describe the original credential")
	}
	return fingerprint
}

func TestNativeSARIFKeepsOriginalFindingsAndFailBehavior(t *testing.T) {
	nativeBinary(t)
	requireInPlaceSecurity(t)
	dir := t.TempDir()
	path := writeSource(t, dir, "original.go", nativeTestSource, 0600)
	ordinary := nativeSARIFCommand(t, "filesystem", path)
	fingerprint := assertNativeSARIF(t, ordinary, 0, path, true)
	assertSource(t, path, nativeTestSource)
	assertNoStagedFiles(t, dir)

	inPlace := nativeSARIFCommand(t, "--fail", "filesystem", "--in-place", path)
	if got := assertNativeSARIF(t, inPlace, 183, path, true); got != fingerprint {
		t.Fatal("in-place SARIF changed the original finding fingerprint")
	}
	redacted := strings.ReplaceAll(nativeTestSource, nativeTestSecret, "REDACTED")
	assertSource(t, path, redacted)
	assertNoStagedFiles(t, dir)

	second := nativeSARIFCommand(t, "--fail", "filesystem", "--in-place", path)
	assertNativeSARIF(t, second, 0, path, false)
	assertSource(t, path, redacted)
	assertNoStagedFiles(t, dir)
}
