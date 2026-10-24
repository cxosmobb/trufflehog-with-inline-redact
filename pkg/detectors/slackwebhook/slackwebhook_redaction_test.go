package slackwebhook

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
)

func TestSlackWebhookSourceRedactionCapturesCompleteToken(t *testing.T) {
	for name, prefix := range map[string]string{
		"service":  "https://hooks.slack.com/services/T00000000/B00000000/",
		"workflow": "https://hooks.slack.com/workflows/T00000000/A00000000/123456789012345678/",
	} {
		for _, length := range []int{23, 24, 25, 26, 32, 128} {
			t.Run(name+"/length-"+strconv.Itoa(length), func(t *testing.T) {
				// Synthetic repeated text, never a real Slack credential.
				token := strings.Repeat("q", length)
				url := prefix + token
				input := []byte("WEBHOOK=\"" + url + "?unrelated=42\"; keep original text\r\n")
				s := Scanner{}
				ordinary, err := s.FromData(context.Background(), false, input)
				if err != nil || len(ordinary) != 1 {
					t.Fatal("ordinary candidate extraction failed")
				}
				wantOrdinary := prefix + token[:min(length, 25)]
				if string(ordinary[0].Raw) != wantOrdinary || ordinary[0].SecretParts["key"] != wantOrdinary {
					t.Fatal("ordinary candidate extraction changed")
				}
				ctx := detectors.WithSourceRedaction(context.Background())
				results, err := s.FromData(ctx, false, input)
				if err != nil || len(results) != 1 || string(results[0].Raw) != url || results[0].SecretParts["key"] != url {
					t.Fatal("source redaction did not capture the complete terminal token")
				}
			})
		}
	}
}
