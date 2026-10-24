package redaction

import (
	"bytes"
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/slackwebhook"
)

func TestSlackWebhookLongSourceTokenRoundTrip(t *testing.T) {
	for name, prefix := range map[string]string{
		"service":  "https://hooks.slack.com/services/T00000000/B00000000/",
		"workflow": "https://hooks.slack.com/workflows/T00000000/A00000000/123456789012345678/",
	} {
		for _, length := range []int{26, 32, 128} {
			t.Run(name+"/length-"+strconv.Itoa(length), func(t *testing.T) {
				// WrongSecrets contains a 32-character dummy terminal segment.
				// Repeated synthetic text exercises the same truncated-match shape.
				token := strings.Repeat("q", length)
				source := "WEBHOOK=\"" + prefix + token + "?unrelated=42\"; keep=original\r\n"
				input := []byte(source)
				d := &slackwebhook.Scanner{}
				ordinary, err := d.FromData(context.Background(), false, input)
				if err != nil || len(ordinary) != 1 || string(ordinary[0].Raw) != prefix+token[:25] {
					t.Fatal("fixture did not exercise ordinary truncated webhook extraction")
				}
				scanner, err := New([]detectors.Detector{d})
				if err != nil {
					t.Fatal(err)
				}
				output, report, err := scanner.Redact(context.Background(), input)
				if err != nil {
					t.Fatal(err)
				}
				want := "WEBHOOK=\"" + prefix + Marker + "?unrelated=42\"; keep=original\r\n"
				if string(output) != want || report.Replacements != 1 || !bytes.Equal(input, []byte(source)) {
					t.Fatal("complete token was not replaced or unrelated source bytes changed")
				}
				after, err := d.FromData(context.Background(), false, output)
				if err != nil || len(after) != 0 {
					t.Fatal("ordinary scan retained a webhook after redaction")
				}
				again, report, err := scanner.Redact(context.Background(), output)
				if err != nil || !bytes.Equal(again, output) || report.Replacements != 0 {
					t.Fatal("webhook source redaction was not idempotent")
				}
			})
		}
	}
}
