package redaction

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/jdbc"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/postgres"
)

func TestJDBCSourceWithPasswordFreeURLRoundTrip(t *testing.T) {
	// WrongSecrets Challenge 58 combines a harmless database URL with a URL
	// carrying a password. Keep the Java source and public connection metadata.
	const secret = "syntheticSensitivePasswordREDACTEDsuffix"
	const source = "// public database configuration\r\n" +
		"String endpoint = \"jdbc:postgresql://db.invalid:5432/public\";\r\n" +
		"String credential = \"jdbc:postgresql://db.invalid:5432/public?user=public&password=" + secret + "&sslmode=require\";\r\n"
	ds := []detectors.Detector{jdbc.New(), postgres.New()}
	scanner, err := New(ds)
	if err != nil {
		t.Fatal(err)
	}
	input := []byte(source)
	countFindings := func(data []byte) int {
		t.Helper()
		count := 0
		for _, detector := range ds {
			results, err := detector.FromData(context.Background(), false, data)
			if err != nil {
				t.Fatal(err)
			}
			for _, result := range results {
				if falsePositive, _ := detectors.GetFalsePositiveCheck(detector)(result); !falsePositive {
					count++
				}
			}
		}
		return count
	}
	if countFindings(input) == 0 {
		t.Fatal("original fixture produced no credential findings")
	}
	output, report, err := scanner.Redact(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if string(output) != strings.ReplaceAll(source, secret, Marker) || report.Replacements != 1 || !bytes.Equal(input, []byte(source)) {
		t.Fatal("source context changed or the exact sensitive password was not replaced")
	}
	if countFindings(output) != 0 {
		t.Fatal("ordinary scan reported a public URL or an exact redaction marker")
	}
	again, report, err := scanner.Redact(context.Background(), output)
	if err != nil || !bytes.Equal(again, output) || report.Replacements != 0 {
		t.Fatal("redaction was not idempotent")
	}
}

func TestConnectionSourceWithholdsUnreviewedCredentialProperties(t *testing.T) {
	scanner, err := New([]detectors.Detector{jdbc.New(), postgres.New()})
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{
		"jdbc:mysql://db.invalid/public?user=public&password1=syntheticAlternateCredential",
		"jdbc:mysql://db.invalid/public?user=public&password2=syntheticAlternateCredential",
		"jdbc:mysql://db.invalid/public?user=public&password3=syntheticAlternateCredential",
		"jdbc:postgresql://db.invalid/public?user=public&sslpassword=syntheticAlternateCredential",
		"jdbc:postgresql://db.invalid/public?password=REDACTED&ssl=true&sslpassword=syntheticAlternateCredential",
		"jdbc:postgresql://db.invalid/public?password=REDACTED&ssl=syntheticAlternateCredential",
		"jdbc:mysql://db.invalid/public?password=REDACTED&futureCredential=syntheticAlternateCredential",
		"jdbc:mysql://db.invalid/public?password=syntheticSensitivePassword&futureCredential=syntheticAlternateCredential",
		"jdbc:mysql://address=(host=db.invalid)(user=public)(password=syntheticAlternateCredential)/public",
		"jdbc:mysql://first.invalid,second.invalid/public?password=syntheticAlternateCredential",
		"jdbc:mysql://public:REDACTED@db.invalid/public#password=syntheticAlternateCredential",
		"postgresql://public:REDACTED@db.invalid/public?sslpassword=syntheticAlternateCredential",
		"postgresql://public:REDACTED@db.invalid/public?futureCredential=syntheticAlternateCredential",
		"postgresql://public:syntheticSensitivePassword@db.invalid/public?futureCredential=syntheticAlternateCredential",
		"postgresql://public:REDACTED@db.invalid/public#password=syntheticAlternateCredential",
	} {
		input := []byte(source)
		output, _, err := scanner.Redact(context.Background(), input)
		if err == nil || output != nil || !bytes.Equal(input, []byte(source)) {
			t.Fatal("unreviewed connection properties were released or changed")
		}
	}
}

func TestJDBCSourceWithSSLFlagRoundTrip(t *testing.T) {
	scanner, err := New([]detectors.Detector{jdbc.New(), postgres.New()})
	if err != nil {
		t.Fatal(err)
	}
	for _, scheme := range []string{"jdbc:postgresql", "postgresql"} {
		for _, ssl := range []string{"true", "false", ""} {
			const password = "syntheticSensitivePasswordForSSLMetadata"
			source := scheme + "://db.invalid/public?user=public&password=" + password + "&ssl=" + ssl
			input := []byte(source)
			output, report, err := scanner.Redact(context.Background(), input)
			if err != nil || string(output) != strings.Replace(source, password, Marker, 1) || report.Replacements != 1 || string(input) != source {
				t.Fatal("reviewed SSL metadata changed or the sensitive password was not redacted exactly")
			}
			again, report, err := scanner.Redact(context.Background(), output)
			if err != nil || !bytes.Equal(again, output) || report.Replacements != 0 {
				t.Fatal("a reviewed SSL flag prevented idempotent redaction")
			}
		}
	}
}
