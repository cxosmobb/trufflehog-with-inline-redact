package redaction

import (
	"bytes"
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/azuresastoken"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/gcp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/jdbc"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

type securityDetector struct {
	*testDetector
	fromData func(context.Context, []byte) ([]detectors.Result, error)
}

func (d securityDetector) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	if verify {
		panic("verification must remain disabled")
	}
	return d.fromData(ctx, data)
}

type capturingLog struct{ called *bool }

func (s capturingLog) Init(logr.RuntimeInfo)          {}
func (s capturingLog) Enabled(int) bool               { return true }
func (s capturingLog) Info(int, string, ...any)       { *s.called = true }
func (s capturingLog) Error(error, string, ...any)    { *s.called = true }
func (s capturingLog) WithValues(...any) logr.LogSink { return s }
func (s capturingLog) WithName(string) logr.LogSink   { return s }

func TestSecurityDetectorPanicWithholdsSecrets(t *testing.T) {
	d := securityDetector{testDetector: &testDetector{secret: "sensitivePanicPayload"}, fromData: func(context.Context, []byte) ([]detectors.Result, error) {
		panic("sensitivePanicPayload")
	}}
	s, _ := New([]detectors.Detector{d})
	output, _, err := s.Redact(context.Background(), []byte("sensitivePanicPayload"))
	if output != nil || err == nil || strings.Contains(err.Error(), "sensitivePanicPayload") {
		t.Fatal("panic exposed source or credential diagnostics")
	}
}

func TestSecurityDetectorLogsAreDiscarded(t *testing.T) {
	called := false
	d := securityDetector{testDetector: &testDetector{secret: "loggingSensitivePayload"}, fromData: func(ctx context.Context, data []byte) ([]detectors.Result, error) {
		logContext.AddLogger(ctx).Logger().Info("sensitive source", "data", string(data))
		logContext.AddLogger(ctx).Logger().Error(nil, "sensitive source", "data", string(data))
		return nil, nil
	}}
	s, _ := New([]detectors.Detector{d})
	ctx := logContext.WithLogger(context.Background(), logr.New(capturingLog{&called}))
	output, _, err := s.Redact(ctx, []byte("loggingSensitivePayload"))
	if err != nil || string(output) != "loggingSensitivePayload" || called {
		t.Fatal("redaction allowed detector context logs to expose source")
	}
}

func TestSecurityConstructorOwnsDetectorList(t *testing.T) {
	d := &testDetector{secret: "constructorSensitivePayload", parts: map[string]string{"key": "constructorSensitivePayload"}}
	ds := []detectors.Detector{d}
	s, err := New(ds)
	if err != nil {
		t.Fatal(err)
	}
	ds[0] = nil
	output, _, err := s.Redact(context.Background(), []byte(`token="constructorSensitivePayload"`))
	if err != nil || string(output) != `token="REDACTED"` {
		t.Fatal("caller mutation changed scanner configuration")
	}
	var nilDetector *testDetector
	if s, err := New([]detectors.Detector{nilDetector}); s != nil || err == nil {
		t.Fatal("typed-nil detector accepted")
	}
}

func TestSecurityBoundedChunksPreserveBoundarySecrets(t *testing.T) {
	fixture := &testDetector{secret: "boundarySensitivePayload", parts: map[string]string{"key": "boundarySensitivePayload"}}
	maxSeen := 0
	d := securityDetector{testDetector: fixture, fromData: func(ctx context.Context, data []byte) ([]detectors.Result, error) {
		if len(data) > maxSeen {
			maxSeen = len(data)
		}
		return fixture.FromData(ctx, false, data)
	}}
	s, _ := New([]detectors.Detector{d})
	input := strings.Repeat(" ", sources.DefaultChunkSize-10) + `token="` + fixture.secret + `";` + strings.Repeat(" ", sources.TotalChunkSize*3) + `token="` + fixture.secret + `";`
	output, report, err := s.Redact(context.Background(), []byte(input))
	if err != nil || string(output) != strings.ReplaceAll(input, fixture.secret, Marker) || report.Replacements != 2 || maxSeen > sources.TotalChunkSize {
		t.Fatal("bounded scan lost a boundary credential or changed source context")
	}
}

func TestSecurityDetectorResultBudget(t *testing.T) {
	d := securityDetector{testDetector: &testDetector{secret: "budget"}, fromData: func(context.Context, []byte) ([]detectors.Result, error) {
		return make([]detectors.Result, maxResultsPerCall+1), nil
	}}
	s, _ := New([]detectors.Detector{d})
	output, _, err := s.Redact(context.Background(), []byte("budget"))
	if output != nil || err == nil || !strings.Contains(err.Error(), "result limit") {
		t.Fatal("unbounded detector results accepted")
	}
}

func TestSecurityRepeatedMultipartFindingsUseUniqueSourceEdits(t *testing.T) {
	fixture := &testDetector{secret: "repeatedSensitivePayload"}
	d := securityDetector{testDetector: fixture, fromData: func(_ context.Context, data []byte) ([]detectors.Result, error) {
		if !bytes.Contains(data, []byte(fixture.secret)) {
			return nil, nil
		}
		results := make([]detectors.Result, maxUniqueFindings)
		for i := range results {
			results[i] = detectors.Result{DetectorType: detector_typepb.DetectorType_Twilio, SecretParts: map[string]string{"id": strconv.Itoa(i), "key": fixture.secret}}
		}
		return results, nil
	}}
	s, _ := New([]detectors.Detector{d})
	input := strings.Repeat(`token="`+fixture.secret+`";`, 40)
	output, report, err := s.Redact(context.Background(), []byte(input))
	if err != nil || string(output) != strings.ReplaceAll(input, fixture.secret, Marker) || report.Replacements != 40 {
		t.Fatal("duplicate multipart combinations exhausted the edit budget for the same source occurrences")
	}
}

func TestSecurityStructuredDuplicateSecrets(t *testing.T) {
	for _, tc := range []struct {
		name     string
		detector detectors.Detector
		source   string
		secrets  []string
	}{
		{"JDBC userinfo and query", jdbc.New(), "jdbc:postgresql://public:firstSensitiveSecret@host.invalid/db?user=public&password=secondSensitiveSecret&sslmode=require", []string{"firstSensitiveSecret", "secondSensitiveSecret"}},
		{"JDBC DSN userinfo and query", jdbc.New(), "jdbc:mysql://public:firstSensitiveSecret@tcp(host.invalid:3307)/db?password=secondSensitiveSecret", []string{"firstSensitiveSecret", "secondSensitiveSecret"}},
		{"JDBC repeated password", jdbc.New(), "jdbc:sqlserver://host.invalid;user=public;password=firstSensitiveSecret;password=secondSensitiveSecret;encrypt=true", []string{"firstSensitiveSecret", "secondSensitiveSecret"}},
		{"SAS repeated signature", &azuresastoken.Scanner{}, "https://publicstore.blob.core.windows.net/container/blob?sp=r&sv=2026-01-01&sr=b&se=2026-12-31T01:02:03Z&sig=firstSensitiveSignature&sig=secondSensitiveSignature", []string{"firstSensitiveSignature", "secondSensitiveSignature"}},
		{"GCP repeated private key", &gcp.Scanner{}, `{"client_email":"public-id","auth_provider_x509_cert_url":"https://public.invalid/cert","private_key":"firstSensitiveSecret","private_key":"secondSensitiveSecret"}`, []string{"firstSensitiveSecret", "secondSensitiveSecret"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scanner, err := New([]detectors.Detector{tc.detector})
			if err != nil {
				t.Fatal(err)
			}
			input := []byte(tc.source)
			output, report, err := scanner.Redact(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			want := tc.source
			for _, secret := range tc.secrets {
				want = strings.ReplaceAll(want, secret, Marker)
			}
			if string(output) != want || report.Replacements != len(tc.secrets) {
				t.Fatal("not all structured secret values were replaced with their context intact")
			}
			if !bytes.Equal(input, []byte(tc.source)) {
				t.Fatal("caller input changed")
			}
		})
	}
}

func TestSecurityGCPDuplicatePrivateKeys(t *testing.T) {
	source := `{"client_email":"public-id","private_key":"firstSensitiveSecret","private_key":"secondSensitiveSecret"}`
	spans, err := Resolve([]byte(source), []detectors.Result{{DetectorType: detector_typepb.DetectorType_GCP, SecretParts: map[string]string{"key": source}}})
	if err != nil {
		t.Fatal(err)
	}
	var edits []edit
	for _, s := range spans {
		edits = append(edits, edit{s.Start, s.End, []byte(Marker)})
	}
	output, _, err := applyEdits([]byte(source), edits)
	if err != nil || string(output) != `{"client_email":"public-id","private_key":"REDACTED","private_key":"REDACTED"}` {
		t.Fatal("duplicate JSON key concealed a private-key value")
	}
}

func TestSecurityMalformedConnectionWithholdsSource(t *testing.T) {
	input := []byte("jdbc:postgresql://public:first%GGSecret@host.invalid/db?password=secondSensitiveSecret")
	d := jdbc.New()
	ctx := logContext.WithLogger(context.Background(), logr.Discard())
	results, err := d.FromData(ctx, false, input)
	if err != nil || len(results) == 0 {
		t.Fatal("fixture did not exercise real JDBC extraction")
	}
	scanner, err := New([]detectors.Detector{d})
	if err != nil {
		t.Fatal(err)
	}
	output, _, err := scanner.Redact(ctx, input)
	if err == nil || output != nil {
		t.Fatal("a query password authorized output with an unparsed userinfo credential")
	}
}
