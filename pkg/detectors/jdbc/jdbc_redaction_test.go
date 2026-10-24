package jdbc

import (
	"context"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
)

func TestJDBCPasswordFalsePositives(t *testing.T) {
	for _, tc := range []struct {
		name string
		conn string
		want bool
	}{
		{"public URL", "jdbc:postgresql://db.invalid:5432/public", true},
		{"public username", "jdbc:postgresql://public@db.invalid/public", true},
		{"empty query password", "jdbc:mysql://db.invalid/public?password=", true},
		{"query marker", "jdbc:postgresql://db.invalid/public?user=public&password=REDACTED", true},
		{"SSL true metadata", "jdbc:postgresql://db.invalid/public?user=public&password=REDACTED&ssl=true", true},
		{"SSL false metadata", "jdbc:postgresql://db.invalid/public?user=public&password=REDACTED&ssl=false", true},
		{"SSL empty metadata", "jdbc:postgresql://db.invalid/public?user=public&password=REDACTED&ssl=", true},
		{"SSL unknown value", "jdbc:postgresql://db.invalid/public?password=REDACTED&ssl=syntheticAlternateCredential", false},
		{"userinfo marker", "jdbc:mysql://public:REDACTED@db.invalid/public", true},
		{"all markers", "jdbc:postgresql://public:REDACTED@db.invalid/public?password=REDACTED&password=REDACTED", true},
		{"encoded marker", "jdbc:postgresql://public:%52EDACTED@db.invalid/public", true},
		{"real password", "jdbc:postgresql://db.invalid/public?password=syntheticSensitivePassword", false},
		{"marker substring", "jdbc:postgresql://public:REDACTEDsuffix@db.invalid/public", false},
		{"marker prefix", "jdbc:mysql://public:prefixREDACTED@db.invalid/public", false},
		{"mixed userinfo", "jdbc:postgresql://public:syntheticSensitivePassword@db.invalid/public?password=REDACTED", false},
		{"mixed query", "jdbc:postgresql://public:REDACTED@db.invalid/public?password=syntheticSensitivePassword", false},
		{"duplicate password", "jdbc:postgresql://db.invalid/public?password=syntheticSensitivePassword&password=REDACTED", false},
		{"malformed userinfo", "jdbc:postgresql://public:malformed%GGPassword@db.invalid/public?password=REDACTED", false},
		{"opaque connection", "jdbc:oracle:thin:public:syntheticSensitivePassword@db.invalid:1521:public", false},
		{"unsupported connection", "jdbc:unknown://db.invalid/public", false},
		{"unparsed property", "jdbc:sqlserver://db.invalid;user=public;password=REDACTED", false},
		{"MFA password one", "jdbc:mysql://db.invalid/public?password1=syntheticAlternateCredential", false},
		{"MFA password two", "jdbc:mysql://db.invalid/public?password2=syntheticAlternateCredential", false},
		{"MFA password three", "jdbc:mysql://db.invalid/public?password3=syntheticAlternateCredential", false},
		{"SSL key password", "jdbc:postgresql://db.invalid/public?sslpassword=syntheticAlternateCredential", false},
		{"unknown property with marker", "jdbc:mysql://db.invalid/public?password=REDACTED&futureCredential=syntheticAlternateCredential", false},
		{"unknown property with real password", "jdbc:mysql://db.invalid/public?password=syntheticSensitivePassword&futureCredential=syntheticAlternateCredential", false},
		{"host properties", "jdbc:mysql://address=(host=db.invalid)(user=public)(password=syntheticAlternateCredential)/public", false},
		{"fragment credential", "jdbc:mysql://public:REDACTED@db.invalid/public#password=syntheticAlternateCredential", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := Scanner{}
			result := detectors.Result{Raw: []byte(tc.conn)}
			if got, _ := s.IsFalsePositive(result); got != tc.want {
				t.Fatal("incorrect credential classification")
			}
			result.Verified = true
			if got, _ := s.IsFalsePositive(result); got {
				t.Fatal("verified credential was hidden")
			}
		})
	}
}

func TestJDBCSourceRedactionOmitsOnlyPasswordFreeURLs(t *testing.T) {
	for _, tc := range []struct {
		name string
		conn string
		want int
	}{
		{"password-free URL", "jdbc:postgresql://db.invalid:5432/public", 0},
		{"password-free SSL URL", "jdbc:postgresql://db.invalid:5432/public?ssl=true", 0},
		{"query password with SSL", "jdbc:postgresql://db.invalid/public?user=public&password=syntheticSensitivePassword&ssl=true", 1},
		{"query password", "jdbc:postgresql://db.invalid/public?user=public&password=syntheticSensitivePassword", 1},
		{"malformed credential", "jdbc:postgresql://public:malformed%GGPassword@db.invalid/public?password=REDACTED", 1},
		{"unsupported syntax", "jdbc:oracle:thin:public:syntheticSensitivePassword@db.invalid:1521:public", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := Scanner{}
			ordinary, err := s.FromData(context.Background(), false, []byte(tc.conn))
			if err != nil || len(ordinary) != 1 {
				t.Fatal("ordinary candidate extraction changed")
			}
			ctx := detectors.WithSourceRedaction(context.Background())
			results, err := s.FromData(ctx, false, []byte(tc.conn))
			if err != nil || len(results) != tc.want {
				t.Fatal("source redaction dropped a possible credential or retained metadata")
			}
		})
	}
}

func TestJDBCSourceRedactionRejectsUnreviewedCredentialSyntax(t *testing.T) {
	for _, conn := range []string{
		"jdbc:mysql://db.invalid/public?user=public&password1=syntheticAlternateCredential",
		"jdbc:mysql://db.invalid/public?user=public&password2=syntheticAlternateCredential",
		"jdbc:mysql://db.invalid/public?user=public&password3=syntheticAlternateCredential",
		"jdbc:postgresql://db.invalid/public?user=public&sslpassword=syntheticAlternateCredential",
		"jdbc:postgresql://db.invalid/public?password=REDACTED&ssl=true&sslpassword=syntheticAlternateCredential",
		"jdbc:postgresql://db.invalid/public?password=REDACTED&ssl=syntheticAlternateCredential",
		"jdbc:mysql://db.invalid/public?password=REDACTED&futureCredential=syntheticAlternateCredential",
		"jdbc:mysql://db.invalid/public?password=syntheticSensitivePassword&futureCredential=syntheticAlternateCredential",
		"jdbc:mysql://public:REDACTED@db.invalid/public?sslpassword=syntheticAlternateCredential",
		"jdbc:mysql://db.invalid/public?password%32=syntheticAlternateCredential",
		"jdbc:mysql://address=(host=db.invalid)(user=public)(password=syntheticAlternateCredential)/public",
		"jdbc:mysql://tcp(address=(host=db.invalid)(password=syntheticAlternateCredential))/public",
		"jdbc:mysql://public:REDACTED@db.invalid/public#password=syntheticAlternateCredential",
	} {
		s := Scanner{}
		ordinary, err := s.FromData(context.Background(), false, []byte(conn))
		if err != nil || len(ordinary) != 1 {
			t.Fatal("ordinary candidate extraction changed")
		}
		if hidden, _ := s.IsFalsePositive(ordinary[0]); hidden {
			t.Fatal("an unreviewed credential format was hidden")
		}
		results, err := s.FromData(detectors.WithSourceRedaction(context.Background()), false, []byte(conn))
		if err == nil || len(results) != 0 {
			t.Fatal("source redaction accepted unreviewed credential properties")
		}
	}
}

func TestJDBCSourceRedactionRejectsTruncatedMultiHostURL(t *testing.T) {
	const conn = "jdbc:mysql://first.invalid,second.invalid/public?password=syntheticAlternateCredential"
	s := Scanner{}
	ordinary, err := s.FromData(context.Background(), false, []byte(conn))
	if err != nil || len(ordinary) != 1 {
		t.Fatal("ordinary candidate extraction changed")
	}
	results, err := s.FromData(detectors.WithSourceRedaction(context.Background()), false, []byte(conn))
	if err == nil || len(results) != 0 {
		t.Fatal("a truncated multi-host URI was treated as complete public metadata")
	}
}

func TestJDBCSourceRedactionRetainsIgnorePatternBehavior(t *testing.T) {
	const conn = "jdbc:mysql://first.invalid,second.invalid/public?password=syntheticAlternateCredential"
	s := New(WithIgnorePattern([]string{`first\.invalid`}))
	results, err := s.FromData(detectors.WithSourceRedaction(context.Background()), false, []byte(conn))
	if err != nil || len(results) != 0 {
		t.Fatal("an explicitly ignored candidate bypassed the existing ignore behavior")
	}
}
