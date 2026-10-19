package decoders

import (
	"bytes"
	"math/rand"
	"strings"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func TestEscapedUnicodeRedactionMatchesUpstreamSemantics(t *testing.T) {
	fragments := []string{
		`plain`, `\u0073`, `\\u0074`, `\U0001F600`, `\u{263a}`,
		`\x{65}`, `\73 `, `\65\63 `, `&#x72;`, `%u0065`,
		`U+0074 `, `U+0074;`, `U+D800`, `\uD800`, `\U00110000`,
		`\u{110000}`, `\x{ffffff}`, `&#x110000;`, "\xff\xfe", `\`,
	}
	check := func(input []byte) {
		t.Helper()
		before := bytes.Clone(input)
		decoder := &EscapedUnicode{}
		expected := decoder.FromChunk(&sources.Chunk{Data: input})
		actual := decoder.FromChunkForRedaction(&sources.Chunk{Data: input})
		if (actual == nil) != (expected == nil) || actual != nil && !bytes.Equal(actual.Data, expected.Data) {
			t.Fatalf("linear redaction audit disagrees with upstream decoding for %q", input)
		}
		if !bytes.Equal(input, before) {
			t.Fatal("redaction decoder mutated its caller's source")
		}
	}
	for _, fragment := range fragments {
		check([]byte("prefix " + fragment + " suffix"))
	}
	random := rand.New(rand.NewSource(739))
	for round := 0; round < 500; round++ {
		var input strings.Builder
		for i := 0; i < 20; i++ {
			input.WriteString(fragments[random.Intn(len(fragments))])
		}
		check([]byte(input.String()))
	}
}

func TestEscapedUnicodeRedactionDenseSource(t *testing.T) {
	const count = 1 << 18
	input := []byte(strings.Repeat(`\u0073`, count) + " safe=unchanged")
	actual := (&EscapedUnicode{}).FromChunkForRedaction(&sources.Chunk{Data: input})
	if actual == nil || string(actual.Data) != strings.Repeat("s", count)+" safe=unchanged" {
		t.Fatal("escape-dense source was not decoded accurately")
	}
}

func BenchmarkEscapedUnicodeRedactionDense(b *testing.B) {
	input := []byte(strings.Repeat(`\u0073`, 1<<16))
	b.SetBytes(int64(len(input)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		(&EscapedUnicode{}).FromChunkForRedaction(&sources.Chunk{Data: input})
	}
}
