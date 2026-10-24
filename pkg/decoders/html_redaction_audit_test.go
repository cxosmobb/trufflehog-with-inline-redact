package decoders

import (
	"bytes"
	"strings"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func htmlAuditFixture(t *testing.T, input string) ([]byte, []HTMLAuditUnit) {
	t.Helper()
	d := &HTML{}
	ordinary := d.FromChunkForRedaction(&sources.Chunk{Data: []byte(input)})
	audited, units, err := d.FromChunkForRedactionAudit(&sources.Chunk{Data: []byte(input)})
	if err != nil || ordinary == nil || audited == nil || !bytes.Equal(ordinary.Data, audited.Data) {
		t.Fatal("HTML provenance changed the ordinary decoder's bytes")
	}
	previous := 0
	for _, unit := range units {
		if unit.Start < previous || unit.End <= unit.Start || unit.End > len(audited.Data) || !strings.Contains(input, string(audited.Data[unit.Start:unit.End])) {
			t.Fatal("HTML provenance is not a sorted unchanged source interval")
		}
		previous = unit.End
	}
	return audited.Data, units
}

func htmlAuditOwns(data []byte, units []HTMLAuditUnit, value string) bool {
	for start := 0; start < len(data); {
		i := bytes.Index(data[start:], []byte(value))
		if i < 0 {
			break
		}
		i += start
		for _, unit := range units {
			if unit.Start <= i && i+len(value) <= unit.End {
				return true
			}
		}
		start = i + len(value)
	}
	return false
}

func TestHTMLRedactionAuditRetainsUnchangedSourceRuns(t *testing.T) {
	for name, input := range map[string]string{
		"text":             `<p>prefixpass4829Suffix</p>`,
		"quoted attribute": `<a title="prefixpass4829Suffix">label</a>`,
		"single attribute": `<a title='prefixpass4829Suffix'>label</a>`,
		"comment":          `<div><!-- prefixpass4829Suffix --></div>`,
		"script":           `<script>const name="prefixpass4829Suffix";</script>`,
		"whitespace":       "<pre>\n \t prefixpass4829Suffix \r\n</pre>",
		"nearby entities":  `<p>&amp; prefixpass4829Suffix &lt;</p>`,
		"syntax highlight": `<span class="hljs-number">prefixpass4829Suffix</span><span class="hljs-string">other</span>`,
		"structural attr":  `<math><annotation-xml encoding="text/html"><p>prefixpass4829Suffix</p></annotation-xml></math>`,
	} {
		t.Run(name, func(t *testing.T) {
			data, units := htmlAuditFixture(t, input)
			if !htmlAuditOwns(data, units, "pass4829") {
				t.Fatal("an unchanged contiguous public identifier lost source proof")
			}
		})
	}
}

func TestHTMLRedactionAuditDoesNotOwnJoinedOrChangedRuns(t *testing.T) {
	for name, input := range map[string]string{
		"inline nodes":      `<span>prefixpa</span><span>ss4829Suffix</span>`,
		"ignored end tag":   `<p>prefixpa</a>ss4829Suffix</p>`,
		"invisible rune":    "<p>prefixpa\u200Bss4829Suffix</p>",
		"NUL":               "<p>prefixpa\x00ss4829Suffix</p>",
		"invisible entity":  `<p>prefixpa&#x200b;ss4829Suffix</p>`,
		"changed entity":    `<p>prefixpa&#x73;s4829Suffix</p>`,
		"attribute entity":  `<a title="prefixpa&#x200b;ss4829Suffix">label</a>`,
		"attribute percent": `<a title="prefixpa%73s4829Suffix">label</a>`,
		"comment invisible": "<div><!-- prefixpa\u200Bss4829Suffix --></div>",
		"ignored duplicate": `<a class="prefixpass4829Suffix">prefixpa</a><span>ss4829Suffix</span>`,
	} {
		t.Run(name, func(t *testing.T) {
			data, units := htmlAuditFixture(t, input)
			if !bytes.Contains(data, []byte("pass4829")) || htmlAuditOwns(data, units, "pass4829") {
				t.Fatal("a joined or transformed component was treated as unchanged source")
			}
		})
	}
	data, units := htmlAuditFixture(t, `<p>prefixpa&amp;amp;ss4829Suffix</p>`)
	if !bytes.Contains(data, []byte("pa&ss4829")) || htmlAuditOwns(data, units, "pa&ss4829") {
		t.Fatal("double-encoded entity bytes authorized an unchanged source interval")
	}
}

func TestHTMLRedactionAuditRejectsExceededBounds(t *testing.T) {
	d := &HTML{}
	for _, input := range [][]byte{
		[]byte("<p>" + strings.Repeat("x ", maxHTMLAuditUnits+1) + "</p>"),
		bytes.Repeat([]byte("x"), (1<<20)+1),
	} {
		output, units, err := d.FromChunkForRedactionAudit(&sources.Chunk{Data: input})
		if err == nil || output != nil || units != nil {
			t.Fatal("excessive HTML provenance was released")
		}
	}
}

func TestHTMLRedactionAuditIgnoresIncompleteOrNestedMarkers(t *testing.T) {
	const prefix = "|synthetic-unit|"
	for _, input := range []string{
		prefix + "s0|prefixpass4829Suffix",
		prefix + "s0|prefix" + prefix + "s1|pass4829" + prefix + "e1|Suffix" + prefix + "e0|",
	} {
		_, units, err := removeHTMLAuditMarkers([]byte(input), prefix, []string{"prefixpass4829Suffix", "pass4829"})
		if err != nil || len(units) != 0 {
			t.Fatal("incomplete or nested sentinels established source ownership")
		}
	}
}
