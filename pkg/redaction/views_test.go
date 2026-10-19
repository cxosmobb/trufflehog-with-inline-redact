package redaction

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func findRedactionView(t *testing.T, input []byte, decoded string) view {
	t.Helper()
	views, err := buildViews(input)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range views {
		if bytes.Equal(candidate.data, []byte(decoded)) {
			return candidate
		}
	}
	t.Fatalf("expected decoded view was not produced")
	return view{}
}

func redactViewNeedles(t *testing.T, input []byte, decoded string, needles ...string) []byte {
	t.Helper()
	candidate := findRedactionView(t, input, decoded)
	var spans []span
	for _, needle := range needles {
		for offset := 0; offset <= len(candidate.data)-len(needle); {
			index := bytes.Index(candidate.data[offset:], []byte(needle))
			if index < 0 {
				break
			}
			start := offset + index
			spans = append(spans, span{start: start, end: start + len(needle)})
			offset = start + len(needle)
		}
	}
	if len(spans) == 0 {
		t.Fatal("test secret absent from decoded view")
	}
	edits, err := candidate.apply(spans)
	if err != nil {
		t.Fatal(err)
	}
	output, err := applyViewEdits(input, edits)
	if err != nil {
		t.Fatal(err)
	}
	return output
}

func TestViewsEscapesPreserveSurroundingSource(t *testing.T) {
	tests := []struct {
		name, encoded, suffix string
	}{
		{"unicode", `\u0073\u0065\u0063\u0072\u0065\u0074`, ""},
		{"double backslash", `\\u0073\\u0065\\u0063\\u0072\\u0065\\u0074`, ""},
		{"brace unicode", `\u{73}\u{65}\u{63}\u{72}\u{65}\u{74}`, ""},
		{"long unicode", `\U00000073\U00000065\U00000063\U00000072\U00000065\U00000074`, ""},
		{"perl", `\x{73}\x{65}\x{63}\x{72}\x{65}\x{74}`, ""},
		{"CSS", `\73 \65 \63 \72 \65 \74`, " "},
		{"code points", `U+0073 U+0065 U+0063 U+0072 U+0065 U+0074`, " "},
		{"html hexadecimal", `&#x73;&#x65;&#x63;&#x72;&#x65;&#x74;`, ""},
		{"html decimal", `&#115;&#101;&#99;&#114;&#101;&#116;`, ""},
		{"percent unicode", `%u0073%u0065%u0063%u0072%u0065%u0074`, ""},
		{"percent URL", `%73%65%63%72%65%74`, ""},
		{"mixed literal and escapes", `s\u0065cr%65&#116;`, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := []byte(`key="` + test.encoded + test.suffix + `"; safe="\u007a"`)
			decoded := `key="secret"; safe="z"`
			output := redactViewNeedles(t, input, decoded, "secret")
			want := `key="REDACTED` + test.suffix + `"; safe="\u007a"`
			if string(output) != want {
				t.Fatalf("context changed: got %q, want %q", output, want)
			}
		})
	}
}

func TestViewsHTMLEntitiesKeepWrappers(t *testing.T) {
	input := []byte(`<a href="token=secret&amp;safe=1">&lt;safe&gt;</a>`)
	decoded := `<a href="token=secret&safe=1"><safe></a>`
	output := redactViewNeedles(t, input, decoded, "secret")
	want := `<a href="token=REDACTED&amp;safe=1">&lt;safe&gt;</a>`
	if string(output) != want {
		t.Fatalf("HTML source changed outside secret: %q", output)
	}
}

func TestViewsUTF16PreservesBOMAndNonASCII(t *testing.T) {
	for _, codec := range []textCodec{codecUTF16LE, codecUTF16BE} {
		t.Run(fmt.Sprint(codec), func(t *testing.T) {
			bom := []byte{0xff, 0xfe}
			if codec == codecUTF16BE {
				bom = []byte{0xfe, 0xff}
			}
			decoded := "😀 header\nkey=secret; safe=café"
			input := append(bytes.Clone(bom), encodeTextReplacement([]byte(decoded), codec)...)
			output := redactViewNeedles(t, input, decoded, "secret")
			want := append(bytes.Clone(bom), encodeTextReplacement([]byte(strings.Replace(decoded, "secret", "REDACTED", 1)), codec)...)
			if !bytes.Equal(output, want) {
				t.Fatal("UTF16 BOM or nonsecret code units changed")
			}
		})
	}
}

func TestViewsUTF16WithoutBOMPreservesWholeLine(t *testing.T) {
	for _, codec := range []textCodec{codecUTF16LE, codecUTF16BE} {
		t.Run(fmt.Sprint(codec), func(t *testing.T) {
			text := "key=\"secret\"; second=\"secret\"; keep=1\r\n"
			input := encodeTextReplacement([]byte(text), codec)
			output := redactViewNeedles(t, input, text, "secret")
			want := encodeTextReplacement([]byte(strings.ReplaceAll(text, "secret", "REDACTED")), codec)
			if !bytes.Equal(output, want) {
				t.Fatal("no-BOM UTF16 secret offsets or source context changed")
			}
			views, err := buildViews(input)
			if err != nil || len(views) != 2 {
				t.Fatal("unambiguous no-BOM UTF16 produced competing shifted projections")
			}
		})
	}
}

func TestViewsMixedUTF16UsesEncodedMarker(t *testing.T) {
	for _, codec := range []textCodec{codecUTF16LE, codecUTF16BE} {
		t.Run(fmt.Sprint(codec), func(t *testing.T) {
			input := append([]byte(`key="`), encodeTextReplacement([]byte("secret"), codec)...)
			input = append(input, []byte(`"; keep=1`)...)
			output := redactViewNeedles(t, input, `key="secret"; keep=1`, "secret")
			want := append([]byte(`key="`), encodeTextReplacement([]byte("REDACTED"), codec)...)
			want = append(want, []byte(`"; keep=1`)...)
			if !bytes.Equal(output, want) {
				t.Fatal("mixed UTF16 text or marker encoding changed")
			}
		})
	}
}

func TestViewsEquivalentMixedUTF16MappingsAgree(t *testing.T) {
	for _, codec := range []textCodec{codecUTF16LE, codecUTF16BE} {
		input := append([]byte(`key="`), encodeTextReplacement([]byte("secret"), codec)...)
		input = append(input, []byte(`"; keep=1`)...)
		views, err := buildViews(input)
		if err != nil {
			t.Fatal(err)
		}
		matches := 0
		for _, candidate := range views {
			if string(candidate.data) != `key="secret"; keep=1` {
				continue
			}
			matches++
			edits, err := candidate.apply([]span{{start: 5, end: 11}})
			if err != nil || len(edits) != 1 || edits[0].start != 5 || edits[0].end != 17 || !bytes.Equal(edits[0].replacement, encodeTextReplacement([]byte("REDACTED"), codec)) {
				t.Fatal("equivalent UTF16 views disagree on source interval or marker byte order")
			}
		}
		if matches == 0 {
			t.Fatal("mixed UTF16 view missing")
		}
	}
}

func TestViewsBase64RedactsDecodedSecretOnly(t *testing.T) {
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		decodedBlob := "user=alice;token=secret;port=443"
		encodedBlob := encoding.EncodeToString([]byte(decodedBlob))
		input := []byte(`x="` + encodedBlob + `"; untouched=1`)
		decoded := `x="` + decodedBlob + `"; untouched=1`
		output := redactViewNeedles(t, input, decoded, "secret")
		redactedBlob := encoding.EncodeToString([]byte("user=alice;token=REDACTED;port=443"))
		want := `x="` + redactedBlob + `"; untouched=1`
		// Alphabet variants that encode identically cannot be distinguished from
		// the original bytes; padded versus raw output is still retained.
		if string(output) != want {
			t.Fatalf("base64 decoded context changed: got %q, want %q", output, want)
		}
	}
}

func TestViewsBase64RepeatedSecretsAndOffsets(t *testing.T) {
	blob := "token=secret;other=secret;safe=1"
	encoded := base64.StdEncoding.EncodeToString([]byte(blob))
	input := []byte(`a="` + encoded + `"; plain=secret; b="` + encoded + `"; tail=secret`)
	decoded := `a="` + blob + `"; plain=secret; b="` + blob + `"; tail=secret`
	output := redactViewNeedles(t, input, decoded, "secret")
	redacted := base64.StdEncoding.EncodeToString([]byte("token=REDACTED;other=REDACTED;safe=1"))
	want := `a="` + redacted + `"; plain=REDACTED; b="` + redacted + `"; tail=REDACTED`
	if string(output) != want {
		t.Fatalf("duplicate base64 blobs or surrounding offsets changed: %q", output)
	}
}

func TestViewsBase64Assignment(t *testing.T) {
	blob := "token=secret;safe=unchanged"
	input := []byte("PAYLOAD=" + base64.StdEncoding.EncodeToString([]byte(blob)))
	output := redactViewNeedles(t, input, "PAYLOAD="+blob, "secret")
	want := "PAYLOAD=" + base64.StdEncoding.EncodeToString([]byte("token=REDACTED;safe=unchanged"))
	if string(output) != want {
		t.Fatalf("assignment changed: %q", output)
	}
}

func TestViewsDecodeCompositions(t *testing.T) {
	t.Run("percent encoded entities", func(t *testing.T) {
		input := []byte(`key="%26%23x73%3B%26%23x65%3B%26%23x63%3B%26%23x72%3B%26%23x65%3B%26%23x74%3B"; keep=1`)
		output := redactViewNeedles(t, input, `key="secret"; keep=1`, "secret")
		if string(output) != `key="REDACTED"; keep=1` {
			t.Fatalf("composed encoding changed context: %q", output)
		}
	})
	t.Run("escaped base64", func(t *testing.T) {
		blob := "token=secret;safe=unchanged"
		encoded := base64.StdEncoding.EncodeToString([]byte(blob))
		var escaped strings.Builder
		for _, value := range encoded {
			fmt.Fprintf(&escaped, `\u%04x`, value)
		}
		input := []byte(`key="` + escaped.String() + `"; keep=1`)
		output := redactViewNeedles(t, input, `key="`+blob+`"; keep=1`, "secret")
		want := `key="` + base64.StdEncoding.EncodeToString([]byte("token=REDACTED;safe=unchanged")) + `"; keep=1`
		if string(output) != want {
			t.Fatalf("escaped base64 context changed: %q", output)
		}
	})
	t.Run("UTF16 base64", func(t *testing.T) {
		blob := "token=secret;safe=unchanged"
		decoded := `key="` + base64.StdEncoding.EncodeToString([]byte(blob)) + `"; keep=1`
		input := append([]byte{0xff, 0xfe}, encodeTextReplacement([]byte(decoded), codecUTF16LE)...)
		output := redactViewNeedles(t, input, `key="`+blob+`"; keep=1`, "secret")
		redacted := `key="` + base64.StdEncoding.EncodeToString([]byte("token=REDACTED;safe=unchanged")) + `"; keep=1`
		want := append([]byte{0xff, 0xfe}, encodeTextReplacement([]byte(redacted), codecUTF16LE)...)
		if !bytes.Equal(output, want) {
			t.Fatal("UTF16 base64 context changed")
		}
	})
}

func TestViewsRejectUnmappableSpans(t *testing.T) {
	t.Run("partial unicode character", func(t *testing.T) {
		candidate := findRedactionView(t, []byte(`\u00e9`), "é")
		if _, err := candidate.apply([]span{{start: 1, end: 2}}); err == nil {
			t.Fatal("accepted partial Unicode character")
		}
	})
	t.Run("base64 boundary", func(t *testing.T) {
		blob := "token=secret;safe=unchanged"
		candidate := findRedactionView(t, []byte("!"+base64.StdEncoding.EncodeToString([]byte(blob))), "!"+blob)
		if _, err := candidate.apply([]span{{start: 0, end: 8}}); err == nil {
			t.Fatal("accepted edit spanning a base64 boundary")
		}
	})
	t.Run("mixed encodings", func(t *testing.T) {
		input := append([]byte("plain"), encodeTextReplacement([]byte("secret"), codecUTF16LE)...)
		candidate := findRedactionView(t, input, "plainsecret")
		if _, err := candidate.apply([]span{{start: 0, end: len(candidate.data)}}); err == nil {
			t.Fatal("accepted secret spanning incompatible text encodings")
		}
	})
	t.Run("invalid offsets", func(t *testing.T) {
		candidate := findRedactionView(t, []byte("secret"), "secret")
		for _, invalid := range []span{{start: -1, end: 2}, {start: 2, end: 2}, {start: 0, end: 7}} {
			if _, err := candidate.apply([]span{invalid}); err == nil {
				t.Fatal("accepted invalid decoded offset")
			}
		}
	})
}

func TestViewsOverlappingSpansAreMerged(t *testing.T) {
	input := []byte(`key=secret; safe=1`)
	candidate := findRedactionView(t, input, string(input))
	edits, err := candidate.apply([]span{{start: 7, end: 10}, {start: 4, end: 9}, {start: 4, end: 10}})
	if err != nil {
		t.Fatal(err)
	}
	output, err := applyViewEdits(input, edits)
	if err != nil || string(output) != `key=REDACTED; safe=1` {
		t.Fatalf("overlapping secret edits changed context: %q, %v", output, err)
	}
}

func TestViewsNeverMutateInput(t *testing.T) {
	input := []byte(`key="\u0073\u0065\u0063\u0072\u0065\u0074"; safe=1`)
	before := bytes.Clone(input)
	redactViewNeedles(t, input, `key="secret"; safe=1`, "secret")
	if !bytes.Equal(input, before) {
		t.Fatal("building or applying a view mutated original input")
	}
}

func TestViewsCompactASCIIProvenance(t *testing.T) {
	// A source-sized ASCII run must not allocate one provenance structure for
	// every UTF16 code unit or unicode escape.
	text := strings.Repeat("a", 1<<20)
	parent := projectedText{data: encodeTextReplacement([]byte(text), codecUTF16LE)}
	decoded, changed := decodeUTF16Text(parent)
	if !changed || decoded.err != nil || decoded.pieces != 1 || string(decoded.data) != text {
		t.Fatal("uniform UTF16 source does not have bounded compact provenance")
	}
	parent = projectedText{data: []byte(strings.Repeat(`\u0061`, 1<<18))}
	decoded, changed = decodeEscapedText(parent)
	if !changed || decoded.err != nil || decoded.pieces != 1 || len(decoded.data) != 1<<18 {
		t.Fatal("uniform escaped source does not have bounded compact provenance")
	}
}

func TestViewsRejectExcessiveProvenance(t *testing.T) {
	// Non-ASCII code points cannot be divided into independently editable
	// bytes. Mixed widths defeat run compaction but still must remain bounded.
	input := []byte(strings.Repeat(`\u00e9\u0061`, maxViewPieces/2+1))
	views, err := buildViews(input)
	if err == nil || views != nil {
		t.Fatal("accepted an input exceeding the provenance resource budget")
	}
}

func TestViewsRejectExcessiveSourceBytes(t *testing.T) {
	views, err := buildViews(make([]byte, maxViewBytes+1))
	if err == nil || views != nil {
		t.Fatal("accepted an input exceeding the decoded source byte budget")
	}
}
