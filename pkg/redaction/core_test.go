package redaction

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detector_typepb"
)

type testDetector struct {
	secret    string
	parts     map[string]string
	err       error
	sawVerify bool
}

func (d *testDetector) FromData(_ context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	d.sawVerify = d.sawVerify || verify
	if d.err != nil {
		return nil, d.err
	}
	if !bytes.Contains(data, []byte(d.secret)) {
		return nil, nil
	}
	return []detectors.Result{{DetectorType: detector_typepb.DetectorType_Twilio, Raw: []byte("public-id"), RawV2: []byte("public-id:" + d.secret), SecretParts: d.parts}}, nil
}
func (d *testDetector) Keywords() []string { return []string{d.secret} }
func (d *testDetector) Type() detector_typepb.DetectorType {
	return detector_typepb.DetectorType_Twilio
}
func (d *testDetector) Description() string { return "synthetic fixture" }

func TestSourceBytesAndRepeatedSecrets(t *testing.T) {
	d := &testDetector{secret: "syntheticSensitiveCredential9385", parts: map[string]string{"sid": "public-id", "key": "syntheticSensitiveCredential9385"}}
	s, _ := New([]detectors.Detector{d})
	input := []byte("sid='public-id'\r\ntoken='" + d.secret + "' // trufflehog:ignore\r\nagain='" + d.secret + "'\r\n")
	before := bytes.Clone(input)
	out, report, err := s.Redact(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	expected := strings.ReplaceAll(string(input), d.secret, Marker)
	if string(out) != expected {
		t.Fatal("original source context changed or a repeated secret survived")
	}
	if !bytes.Equal(input, before) || d.sawVerify || report.Replacements != 2 {
		t.Fatal("input mutation, credential verification, or missing occurrence")
	}
}

func TestFailureWithholdsSource(t *testing.T) {
	for _, d := range []*testDetector{
		{secret: "syntheticSecret", parts: map[string]string{"new_unreviewed_part": "syntheticSecret"}},
		{secret: "syntheticSecret", parts: map[string]string{"key": "absent-from-source"}},
		{secret: "syntheticSecret", parts: map[string]string{"sid": "public-id"}},
		{secret: "syntheticSecret", err: errors.New("error containing syntheticSecret")},
	} {
		s, _ := New([]detectors.Detector{d})
		out, _, err := s.Redact(context.Background(), []byte("token='syntheticSecret'"))
		if err == nil || out != nil {
			t.Fatal("unsafe source was released")
		}
		if strings.Contains(err.Error(), "syntheticSecret") {
			t.Fatal("credential escaped in error")
		}
	}
}

func TestCanceledScanWithholdsSource(t *testing.T) {
	d := &testDetector{secret: "syntheticSecret", parts: map[string]string{"key": "syntheticSecret"}}
	s, _ := New([]detectors.Detector{d})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out, _, err := s.Redact(ctx, []byte(d.secret))
	if !errors.Is(err, context.Canceled) || out != nil {
		t.Fatal("canceled scan released source")
	}
}

func TestPreciseStructuredCredentialRanges(t *testing.T) {
	cases := []struct {
		typ    detector_typepb.DetectorType
		source string
		parts  map[string]string
		want   string
	}{
		{detector_typepb.DetectorType_MongoDB, `mongodb://public-user:p%40ssword@host.invalid/db?tls=true`, map[string]string{"key": `mongodb://public-user:p%40ssword@host.invalid/db?tls=true`}, `mongodb://public-user:REDACTED@host.invalid/db?tls=true`},
		{detector_typepb.DetectorType_JDBC, `jdbc:mysql://host.invalid/db?user=public-user&password=syntheticSensitiveValue&ssl=true`, map[string]string{"connection_string": `jdbc:mysql://host.invalid/db?user=public-user&password=syntheticSensitiveValue&ssl=true`}, `jdbc:mysql://host.invalid/db?user=public-user&password=REDACTED&ssl=true`},
		{detector_typepb.DetectorType_GCP, `{"client_email":"public-id","private_key":"synthetic\nprivate-key"}`, map[string]string{"key": `{"client_email":"public-id","private_key":"synthetic\nprivate-key"}`}, `{"client_email":"public-id","private_key":"REDACTED"}`},
		{detector_typepb.DetectorType_AzureSasToken, `https://public.invalid/blob?sp=r&sig=synthetic%2Fsignature&sv=2026-01-01`, map[string]string{"url": "https://public.invalid/blob", "key": "sp=r&sig=synthetic%2Fsignature&sv=2026-01-01"}, `https://public.invalid/blob?sp=r&sig=REDACTED&sv=2026-01-01`},
		{detector_typepb.DetectorType_SlackWebhook, `https://hooks.slack.com/services/TPUBLIC/BPUBLIC/syntheticSecretComponent`, map[string]string{"key": "https://hooks.slack.com/services/TPUBLIC/BPUBLIC/syntheticSecretComponent"}, `https://hooks.slack.com/services/TPUBLIC/BPUBLIC/REDACTED`},
		{detector_typepb.DetectorType_TwilioApiKey, `key=SKPUBLIC sid=syntheticApiSecret`, map[string]string{"key": "SKPUBLIC", "sid": "syntheticApiSecret"}, `key=SKPUBLIC sid=REDACTED`},
	}
	for _, tc := range cases {
		t.Run(tc.typ.String(), func(t *testing.T) {
			spans, err := Resolve([]byte(tc.source), []detectors.Result{{DetectorType: tc.typ, SecretParts: tc.parts}})
			if err != nil {
				t.Fatal(err)
			}
			var edits []edit
			for _, s := range spans {
				edits = append(edits, edit{s.Start, s.End, []byte(Marker)})
			}
			out, _, err := applyEdits([]byte(tc.source), edits)
			if err != nil || string(out) != tc.want {
				t.Fatal("sensitive component or surrounding source was not preserved precisely")
			}
		})
	}
}

func TestShortSecretsDoNotEraseUnrelatedIdentifiers(t *testing.T) {
	source := []byte(`password="cat"; concatenate="keep"; catapult="keep"`)
	spans, err := Resolve(source, []detectors.Result{{SecretParts: map[string]string{"password": "cat"}}})
	if err != nil || len(spans) != 1 || string(source[spans[0].Start:spans[0].End]) != "cat" {
		t.Fatal("short secret over-redacted context")
	}
}

func TestLongSecretsDoNotEraseUnrelatedIdentifiers(t *testing.T) {
	source := []byte(`password="longpassword"; longpasswordUtility="keep"`)
	spans, err := Resolve(source, []detectors.Result{{SecretParts: map[string]string{"password": "longpassword"}}})
	if err != nil || len(spans) != 1 {
		t.Fatal("long component redacted an unrelated identifier")
	}
	output, _, err := applyEdits(source, []edit{{spans[0].Start, spans[0].End, []byte(Marker)}})
	if err != nil || string(output) != `password="REDACTED"; longpasswordUtility="keep"` {
		t.Fatal("unrelated source changed")
	}
}

func TestReviewedPublicPolicyTypeNames(t *testing.T) {
	for typ := range publicPairedKey {
		if _, ok := detector_typepb.DetectorType_value[typ]; !ok {
			t.Errorf("public component policy refers to unknown detector type %s", typ)
		}
	}
}

func TestConnectionPasswordParameterBoundary(t *testing.T) {
	r := detectors.Result{DetectorType: detector_typepb.DetectorType_JDBC, SecretParts: map[string]string{"connection_string": "jdbc:mysql://host.invalid/db?notpassword=ordinaryvalue"}}
	if spans, err := Resolve([]byte(r.SecretParts["connection_string"]), []detectors.Result{r}); err == nil || spans != nil {
		t.Fatal("ordinary parameter mistaken for password")
	}
}

func TestConnectionPercentEscapeCase(t *testing.T) {
	input := `mongodb://public-user:sensitive%2fpassword@host.invalid/db`
	r := detectors.Result{DetectorType: detector_typepb.DetectorType_MongoDB, SecretParts: map[string]string{"key": input}}
	spans, err := Resolve([]byte(input), []detectors.Result{r})
	if err != nil || len(spans) != 1 || input[spans[0].Start:spans[0].End] != "sensitive%2fpassword" {
		t.Fatal("original password escaping was not mapped")
	}
}

func TestWebhookSourcePreservation(t *testing.T) {
	cases := []struct {
		typ            detector_typepb.DetectorType
		source, secret string
	}{
		{detector_typepb.DetectorType_TinesWebhook, "https://public.tines.com/webhook/publichookidentifier/syntheticSensitiveToken", "syntheticSensitiveToken"},
		{detector_typepb.DetectorType_ZapierWebhook, "https://hooks.zapier.com/hooks/catch/1234567/syntheticSensitiveToken/", "syntheticSensitiveToken"},
		{detector_typepb.DetectorType_MicrosoftTeamsWebhook, "https://public.webhook.office.com/webhookb2/public@tenant/IncomingWebhook/syntheticSensitiveToken/publicchannel", "syntheticSensitiveToken"},
		{detector_typepb.DetectorType_MicrosoftTeamsWebhook, "https://public.environment.api.powerplatform.com/workflow/invoke?api-version=1&sp=public&sig=syntheticSensitiveToken&sv=1.0", "syntheticSensitiveToken"},
	}
	for _, tc := range cases {
		t.Run(tc.typ.String(), func(t *testing.T) {
			spans, err := Resolve([]byte(tc.source), []detectors.Result{{DetectorType: tc.typ, SecretParts: map[string]string{"key": tc.source}}})
			if err != nil || len(spans) != 1 {
				t.Fatal("webhook token was not mapped")
			}
			out, _, err := applyEdits([]byte(tc.source), []edit{{spans[0].Start, spans[0].End, []byte(Marker)}})
			if err != nil || string(out) != strings.Replace(tc.source, tc.secret, Marker, 1) {
				t.Fatal("webhook nonsecret context changed")
			}
		})
	}
}

func TestJDBCVariantSourcePreservation(t *testing.T) {
	for _, source := range []string{
		"jdbc:mysql://user:syntheticSensitiveToken@tcp(host.invalid:3307)/db",
		"jdbc:sqlserver://host.invalid:1433;database=db;user=public;password=syntheticSensitiveToken;encrypt=true",
		"jdbc:postgresql://host.invalid:5432/db?user=public&password=syntheticSensitiveToken&sslmode=require",
	} {
		spans, err := Resolve([]byte(source), []detectors.Result{{DetectorType: detector_typepb.DetectorType_JDBC, SecretParts: map[string]string{"connection_string": source}}})
		if err != nil || len(spans) != 1 {
			t.Fatal("JDBC variant secret not mapped")
		}
		output, _, err := applyEdits([]byte(source), []edit{{spans[0].Start, spans[0].End, []byte(Marker)}})
		if err != nil || string(output) != strings.Replace(source, "syntheticSensitiveToken", Marker, 1) {
			t.Fatal("JDBC nonsecret source changed")
		}
	}
}

func TestConflictingEncodedEditsWithholdSource(t *testing.T) {
	out, _, err := applyEdits([]byte("abcdefghij"), []edit{{0, 6, []byte("encoded1")}, {3, 8, []byte("encoded2")}})
	if out != nil || err == nil {
		t.Fatal("conflicting source projections accepted")
	}
}

func TestSourceEditBudgetUsesFinalSize(t *testing.T) {
	input := bytes.Repeat([]byte("x"), maxViewBytes)
	output, count, err := applyEdits(input, []edit{
		{0, 1, []byte(Marker)},
		{len(input) - 16, len(input), []byte(Marker)},
	})
	if err != nil || count != 2 || len(output) != len(input)-1 {
		t.Fatal("valid final output rejected by an intermediate size estimate")
	}
	if !bytes.HasPrefix(output, []byte(Marker)) || !bytes.HasSuffix(output, []byte(Marker)) || !bytes.Equal(output[len(Marker):len(output)-len(Marker)], input[1:len(input)-16]) {
		t.Fatal("size-boundary edits changed unrelated source bytes")
	}
	output, _, err = applyEdits(input, []edit{{0, 1, []byte(Marker)}})
	if err == nil || output != nil {
		t.Fatal("oversized final output was released")
	}
}

func TestSourceRedactionPreservesSensitiveSubstringsInPublicIdentifiers(t *testing.T) {
	const secret = "pass4829"
	d := securityDetector{testDetector: &testDetector{secret: secret}, fromData: func(_ context.Context, data []byte) ([]detectors.Result, error) {
		if !bytes.Contains(data, []byte(`password="`+secret+`"`)) {
			return nil, nil
		}
		return []detectors.Result{{DetectorType: detector_typepb.DetectorType_Twilio, SecretParts: map[string]string{"key": secret}}}, nil
	}}
	s, _ := New([]detectors.Detector{d})
	input := []byte(`password="pass4829"; pass4829Utility="keep"; prefixpass4829="keep"; prefixpass4829Suffix="keep"; again="pass4829"`)
	want := []byte(`password="REDACTED"; pass4829Utility="keep"; prefixpass4829="keep"; prefixpass4829Suffix="keep"; again="REDACTED"`)
	output, report, err := s.Redact(context.Background(), input)
	if err != nil || !bytes.Equal(output, want) || report.Replacements != 2 {
		t.Fatal("residual audit rejected preserved public identifiers or altered their bytes")
	}
}

func TestResidualAuditUsesMappingBoundariesWithoutMissingOverlaps(t *testing.T) {
	d := &testDetector{secret: "never-present-sensitive-fixture", parts: map[string]string{"key": "never-present-sensitive-fixture"}}
	s, _ := New([]detectors.Detector{d})
	for _, tc := range []struct {
		name, output string
		values       map[string]struct{}
		wantError    bool
	}{
		{"public identifier", `prefixpass4829Suffix pass4829Utility prefixpass4829`, map[string]struct{}{"pass4829": {}}, false},
		{"standalone residual", `password="pass4829"`, map[string]struct{}{"pass4829": {}}, true},
		{"residual after public identifier", `pass4829Utility; password="pass4829"`, map[string]struct{}{"pass4829": {}}, true},
		{"overlapping longer residual", `passwordUtility; value="password"`, map[string]struct{}{"pass": {}, "password": {}}, true},
		{"encoded residual", `password="pa\u0073s4829"`, map[string]struct{}{"pass4829": {}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			work := 0
			err := s.auditOutput(context.Background(), []byte(tc.output), tc.values, &work)
			if (err != nil) != tc.wantError {
				t.Fatal("residual audit disagrees with precise mapping boundaries")
			}
		})
	}
}

func TestResidualAuditBoundsInvalidBoundaryMatches(t *testing.T) {
	d := &testDetector{secret: "never-present-sensitive-fixture", parts: map[string]string{"key": "never-present-sensitive-fixture"}}
	s, _ := New([]detectors.Detector{d})
	work := 0
	output := []byte(strings.Repeat("pass4829Utility ", maxSourceSpans+1))
	err := s.auditOutput(context.Background(), output, map[string]struct{}{"pass4829": {}}, &work)
	if err == nil || err.Error() != "secret audit match limit exceeded; source withheld" {
		t.Fatal("unbounded residual match callbacks were not withheld")
	}
}
func TestResidualAuditRejectsJoinedComponentsWithoutBoundaries(t *testing.T) {
	d := &testDetector{secret: "never-present-sensitive-fixture", parts: map[string]string{"key": "never-present-sensitive-fixture"}}
	s, _ := New([]detectors.Detector{d})
	for name, output := range map[string]string{
		"word prefix":   `<span>prefix</span><span>pa</span><span>ss4829</span>`,
		"word suffix":   `<span>pa</span><span>ss4829</span><span>Suffix</span>`,
		"marker prefix": `<span>REDACTED</span><span>pa</span><span>ss4829</span>`,
	} {
		t.Run(name, func(t *testing.T) {
			work := 0
			if err := s.auditOutput(context.Background(), []byte(output), map[string]struct{}{"pass4829": {}}, &work); err == nil {
				t.Fatal("lossy HTML joining hid an original sensitive component behind a word boundary")
			}
		})
	}
}
func TestResidualHTMLAuditPreservesProvenPublicIdentifiers(t *testing.T) {
	d := &testDetector{secret: "never-present-sensitive-fixture", parts: map[string]string{"key": "never-present-sensitive-fixture"}}
	s, _ := New([]detectors.Detector{d})
	for name, output := range map[string]string{
		"text":                 `<p>prefixpass4829Suffix</p>`,
		"attribute":            `<a title="prefixpass4829Suffix">safe</a>`,
		"comment":              `<!-- prefixpass4829Suffix -->`,
		"transforms elsewhere": `<p>&amp; prefixpass4829Suffix &lt;</p>`,
	} {
		t.Run(name, func(t *testing.T) {
			work := 0
			if err := s.auditOutput(context.Background(), []byte(output), map[string]struct{}{"pass4829": {}}, &work); err != nil {
				t.Fatal("unchanged source identifier was rejected by the HTML residual audit")
			}
		})
	}
}

func TestResidualHTMLAuditRejectsChangedAndCrossUnitComponents(t *testing.T) {
	d := &testDetector{secret: "never-present-sensitive-fixture", parts: map[string]string{"key": "never-present-sensitive-fixture"}}
	s, _ := New([]detectors.Detector{d})
	for name, output := range map[string]string{
		"ignored markup":      `<p>prefixpa</a>ss4829Suffix</p>`,
		"invisible":           "<p>prefixpa\u200Bss4829Suffix</p>",
		"entity":              `<p>prefixpa&#x73;s4829Suffix</p>`,
		"attribute transform": `<a title="prefixpa%73s4829Suffix">safe</a>`,
		"ignored duplicate":   `<a class="prefixpass4829Suffix">prefixpa</a><span>ss4829Suffix</span>`,
	} {
		t.Run(name, func(t *testing.T) {
			work := 0
			if err := s.auditOutput(context.Background(), []byte(output), map[string]struct{}{"pass4829": {}}, &work); err == nil {
				t.Fatal("changed or cross-unit original component escaped the HTML residual audit")
			}
		})
	}
	work := 0
	if err := s.auditOutput(context.Background(), []byte(`<p>prefixpa&amp;amp;ss4829Suffix</p>`), map[string]struct{}{"pa&ss4829": {}}, &work); err == nil {
		t.Fatal("double-encoded source bytes authorized a residual component")
	}
}

func TestResidualHTMLAuditChecksOverlappingPatternsIndependently(t *testing.T) {
	d := &testDetector{secret: "never-present-sensitive-fixture", parts: map[string]string{"key": "never-present-sensitive-fixture"}}
	s, _ := New([]detectors.Detector{d})
	for _, output := range []string{
		`<span>password</span>`,
		`<span>prefixpass</span><span>wordSuffix</span>`,
	} {
		work := 0
		if err := s.auditOutput(context.Background(), []byte(output), map[string]struct{}{"pass": {}, "password": {}}, &work); err == nil {
			t.Fatal("an exempt shorter pattern hid a valid or cross-unit longer component")
		}
	}
}

func TestHTMLResidualProvenanceCannotUseIgnoredDuplicateContext(t *testing.T) {
	const gate = "pairedAuditGateSensitiveValue"
	const secret = "pass4829"
	d := securityDetector{testDetector: &testDetector{secret: gate}, fromData: func(_ context.Context, data []byte) ([]detectors.Result, error) {
		if !bytes.Contains(data, []byte(gate)) || !bytes.Contains(data, []byte(secret)) {
			return nil, nil
		}
		return []detectors.Result{{DetectorType: detector_typepb.DetectorType_Test, SecretParts: map[string]string{"key": gate, "secret": secret}}}, nil
	}}
	s, _ := New([]detectors.Detector{d})
	input := []byte(`<div>first="` + gate + `"; second="` + secret + `"</div><span class="prefixpass4829Suffix"></span><span>prefixpa</span><span>ss4829Suffix</span>`)
	before := bytes.Clone(input)
	output, _, err := s.Redact(context.Background(), input)
	if err == nil || output != nil || !bytes.Equal(input, before) {
		t.Fatal("an ignored duplicate identifier authorized a fragmented paired component after its detector was disabled")
	}
}

func TestHTMLResidualProvenanceIsLazyAndKeepsDetectorViews(t *testing.T) {
	d := &testDetector{secret: "never-present-sensitive-fixture", parts: map[string]string{"key": "never-present-sensitive-fixture"}}
	s, _ := New([]detectors.Detector{d})
	// More than the per-call provenance limit, but no original component is
	// present. No source-unit proof should be built just to scan clean HTML.
	work := 0
	if err := s.auditOutput(context.Background(), []byte("<p>"+strings.Repeat("x ", 4097)+"</p>"), map[string]struct{}{"absentSensitiveValue": {}}, &work); err != nil {
		t.Fatal("clean HTML unnecessarily built residual provenance")
	}
	seen := false
	full := securityDetector{testDetector: &testDetector{secret: "pass4829"}, fromData: func(_ context.Context, data []byte) ([]detectors.Result, error) {
		if string(data) != "prefixpass4829Suffix" {
			return nil, nil
		}
		seen = true
		return []detectors.Result{{DetectorType: detector_typepb.DetectorType_Test, SecretParts: map[string]string{"key": "newSensitiveCandidate"}}}, nil
	}}
	s, _ = New([]detectors.Detector{full})
	work = 0
	if err := s.auditOutput(context.Background(), []byte(`<p>prefixpass4829Suffix</p>`), map[string]struct{}{"pass4829": {}}, &work); err == nil || !seen {
		t.Fatal("HTML residual provenance changed the full post-redaction detector view")
	}
}
