package tru

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
)

// Synthetic placeholders only; neither value is an issued credential.
const (
	syntheticTruKey    = "12345678-1234-1234-1234-123456789abc"
	syntheticTruSecret = "abcdef0123456789abcdef0123"
	syntheticTruHTML   = `<script nonce="ABCDEFGHIJKLMNOPQRSTUVWXYZ">window.enabled=true;window.identifier="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";window.ready=true;window.nonce="ABCDEFGHIJKLMNOPQRSTUVWXYZ";</script>`
)

func checkTruProviderContext(t *testing.T, input, key, secret string) {
	t.Helper()
	for _, mode := range []string{"ordinary", "source"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			if mode == "source" {
				ctx = detectors.WithSourceRedaction(ctx)
			}
			results, err := (Scanner{}).FromData(ctx, false, []byte(input))
			if err != nil {
				t.Fatal("offline Tru detection failed")
			}
			if key == "" {
				if len(results) != 0 {
					t.Fatal("unrelated public context produced a Tru credential")
				}
				return
			}
			if len(results) != 1 || string(results[0].Raw) != key || string(results[0].RawV2) != key+secret || results[0].SecretParts["key"] != key || results[0].SecretParts["secret"] != secret || results[0].Verified {
				t.Fatal("Tru provider context changed credential capture or verification")
			}
		})
	}
}

func TestTruProviderNamespaceContexts(t *testing.T) {
	for _, namespace := range []string{"tru", "TrU", "tru.id", "TRU_ID", "TRU_API_KEY", "tru-id", "my_tru_id", "https://eu.api.tru.id"} {
		t.Run(namespace, func(t *testing.T) {
			input := fmt.Sprintf("%s client_id = '%s'\n%s client_secret = '%s'\n", namespace, syntheticTruKey, namespace, syntheticTruSecret)
			checkTruProviderContext(t, input, syntheticTruKey, syntheticTruSecret)
		})
	}
}

func TestTruRejectsGenericWordContexts(t *testing.T) {
	for _, word := range []string{"true", "trust", "structure", "TRUSTED", "trufflehog", "obtrusive", "intruder", "extrusion", "nottru", "tru2"} {
		t.Run(word, func(t *testing.T) {
			input := fmt.Sprintf("%s id = '%s'\n%s nonce = '%s'\n", word, syntheticTruKey, word, syntheticTruSecret)
			checkTruProviderContext(t, input, "", "")
		})
	}
	t.Run("public HTML nonces and UUID", func(t *testing.T) {
		checkTruProviderContext(t, syntheticTruHTML, "", "")
	})
}

func TestTruProviderContextKeepsFortyCharacterWindow(t *testing.T) {
	for _, gap := range []int{1, 39, 40, 41} {
		t.Run(fmt.Sprint(gap), func(t *testing.T) {
			separator := strings.Repeat(" ", gap)
			input := "tru" + separator + syntheticTruKey + "\ntru" + separator + syntheticTruSecret
			key, secret := syntheticTruKey, syntheticTruSecret
			if gap > 40 {
				key, secret = "", ""
			}
			checkTruProviderContext(t, input, key, secret)
		})
	}
}

func TestTruProviderContextPreservesCredentialAlphabet(t *testing.T) {
	// Preserve the existing detector's accepted punctuation. This change only
	// repairs provider context; it does not infer a narrower credential format.
	for _, punctuation := range []string{".", "_", "/", "[", "]", ":", ";", "<", "=", ">", "?", "@", "\\", "^"} {
		t.Run(punctuation, func(t *testing.T) {
			secret := strings.Repeat("a", 12) + punctuation + strings.Repeat("b", 13)
			input := "tru id = '" + syntheticTruKey + "'\ntru secret = '" + secret + "'"
			checkTruProviderContext(t, input, syntheticTruKey, secret)
		})
	}
}

func TestTruMixedPublicHTMLAndGenuineProviderContext(t *testing.T) {
	input := syntheticTruHTML + strings.Repeat("\n", 80) + "TRU_ID='" + syntheticTruKey + "'\nTRU_SECRET='" + syntheticTruSecret + "'"
	checkTruProviderContext(t, input, syntheticTruKey, syntheticTruSecret)
}
