package postgres

import (
	"context"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
)

func TestPostgresRedactionMarkerFalsePositives(t *testing.T) {
	for _, tc := range []struct {
		name string
		uri  string
		want bool
	}{
		{"userinfo marker", "postgresql://public:REDACTED@db.invalid/public", true},
		{"query marker", "postgresql://db.invalid/public?user=public&password=REDACTED", true},
		{"SSL true metadata", "postgresql://public:REDACTED@db.invalid/public?ssl=true", true},
		{"SSL false metadata", "postgresql://public:REDACTED@db.invalid/public?ssl=false", true},
		{"SSL empty metadata", "postgresql://public:REDACTED@db.invalid/public?ssl=", true},
		{"SSL unknown value", "postgresql://public:REDACTED@db.invalid/public?ssl=syntheticAlternateCredential", false},
		{"all markers", "postgresql://public:REDACTED@db.invalid/public?password=REDACTED&password=REDACTED", true},
		{"encoded marker", "postgresql://public:%52EDACTED@db.invalid/public", true},
		{"real password", "postgresql://public:syntheticSensitivePassword@db.invalid/public", false},
		{"marker substring", "postgresql://public:prefixREDACTEDsuffix@db.invalid/public", false},
		{"mixed userinfo", "postgresql://public:syntheticSensitivePassword@db.invalid/public?password=REDACTED", false},
		{"mixed query", "postgresql://public:REDACTED@db.invalid/public?password=syntheticSensitivePassword", false},
		{"duplicate query", "postgresql://db.invalid/public?user=public&password=syntheticSensitivePassword&password=REDACTED", false},
		{"malformed URI", "postgresql://public:malformed%GGPassword@db.invalid/public?password=REDACTED", false},
		{"no password", "postgresql://public@db.invalid/public", false},
		{"SSL key password", "postgresql://public:REDACTED@db.invalid/public?sslpassword=syntheticAlternateCredential", false},
		{"unknown property with marker", "postgresql://public:REDACTED@db.invalid/public?futureCredential=syntheticAlternateCredential", false},
		{"unknown property with real password", "postgresql://public:syntheticSensitivePassword@db.invalid/public?futureCredential=syntheticAlternateCredential", false},
		{"fragment credential", "postgresql://public:REDACTED@db.invalid/public#password=syntheticAlternateCredential", false},
		{"host properties", "postgresql://public:REDACTED@address=(host=db.invalid)(password=syntheticAlternateCredential)/public", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A normalized connection string can contain only the final password.
			// The original URI must still protect earlier credential values.
			result := detectors.Result{SecretParts: map[string]string{
				"connection_string": "postgresql://public:REDACTED@db.invalid:5432",
			}}
			result.SetPrimarySecretValue(tc.uri)
			s := Scanner{}
			if got, _ := s.IsFalsePositive(result); got != tc.want {
				t.Fatal("incorrect marker classification")
			}
			result.Verified = true
			if got, _ := s.IsFalsePositive(result); got {
				t.Fatal("verified credential was hidden")
			}
		})
	}
}

func TestPostgresMarkerFindingIsFilteredAfterExtraction(t *testing.T) {
	s := Scanner{}
	results, err := s.FromData(context.Background(), false, []byte("postgresql://public:REDACTED@db.invalid:5432/public"))
	if err != nil || len(results) != 1 {
		t.Fatal("ordinary candidate extraction changed")
	}
	if got, _ := s.IsFalsePositive(results[0]); !got {
		t.Fatal("redaction marker remained an ordinary finding")
	}
}

func TestPostgresSourceRedactionRejectsUnreviewedCredentialSyntax(t *testing.T) {
	for _, uri := range []string{
		"postgresql://public:REDACTED@db.invalid/public?sslpassword=syntheticAlternateCredential",
		"postgresql://public:REDACTED@db.invalid/public?ssl=true&sslpassword=syntheticAlternateCredential",
		"postgresql://public:REDACTED@db.invalid/public?ssl=syntheticAlternateCredential",
		"postgresql://public:REDACTED@db.invalid/public?futureCredential=syntheticAlternateCredential",
		"postgresql://public:syntheticSensitivePassword@db.invalid/public?futureCredential=syntheticAlternateCredential",
		"postgresql://public:REDACTED@db.invalid/public?password2=syntheticAlternateCredential",
		"postgresql://public:REDACTED@db.invalid/public#password=syntheticAlternateCredential",
		"postgresql://public:REDACTED@address=(host=db.invalid)(password=syntheticAlternateCredential)/public",
	} {
		s := Scanner{}
		ordinary, err := s.FromData(context.Background(), false, []byte(uri))
		if err != nil || len(ordinary) != 1 {
			t.Fatal("ordinary candidate extraction changed")
		}
		if hidden, _ := s.IsFalsePositive(ordinary[0]); hidden {
			t.Fatal("an unreviewed credential format was hidden")
		}
		results, err := s.FromData(detectors.WithSourceRedaction(context.Background()), false, []byte(uri))
		if err == nil || len(results) != 0 {
			t.Fatal("source redaction accepted unreviewed credential properties")
		}
	}
}
