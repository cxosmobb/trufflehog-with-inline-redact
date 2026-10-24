package redaction

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/tru"
)

func TestTruSourceKeepsPublicHTMLAndRedactsProviderCredentials(t *testing.T) {
	// Generic true values must not turn public CSP/JavaScript data into Tru
	// credentials. All values here are synthetic, including the real candidate.
	const publicHTML = `<script nonce="public:nonce_fragment00001">
const options = {enabled: true, cspScriptNonce: "11111111-2222-3333-4444-555555555555"};
const state = {enabled: true, nonce: "public:nonce_fragment00001"};
</script>`
	const key = "12345678-abcd-1234-abcd-123456789abc"
	const secret = "Abcdef0123456789Abcdef0123"
	config := "\r\n" + strings.Repeat(" ", 80) + "\r\nTRU_API_KEY='" + key + "'\r\nTRU_API_SECRET='" + secret + "'\r\n"
	scanner, err := New([]detectors.Detector{tru.Scanner{}})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, source, want string
		replacements       int
	}{
		{"public-html", publicHTML, publicHTML, 0},
		{"mixed", publicHTML + config, publicHTML + strings.ReplaceAll(strings.ReplaceAll(config, key, Marker), secret, Marker), 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := []byte(test.source)
			output, report, err := scanner.Redact(context.Background(), input)
			if err != nil || string(output) != test.want || report.Replacements != test.replacements || string(input) != test.source {
				t.Fatal("public HTML changed or provider credentials were not replaced precisely")
			}
			findings, err := (tru.Scanner{}).FromData(context.Background(), false, output)
			if err != nil || len(findings) != 0 {
				t.Fatal("ordinary Tru scan retained findings after exact source redaction")
			}
			again, report, err := scanner.Redact(context.Background(), output)
			if err != nil || !bytes.Equal(again, output) || report.Replacements != 0 {
				t.Fatal("public HTML or redacted credentials changed on a second pass")
			}
		})
	}
}
