package decoders

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"strconv"
	"strings"

	regexp "github.com/wasilibs/go-re2"
	"golang.org/x/net/html"

	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

const maxHTMLAuditUnits = 4096

var (
	errHTMLAudit              = errors.New("cannot establish unchanged HTML source units")
	htmlAuditQuotedAttributes = regexp.MustCompile(`[ \t\r\n\f]+([^\s/"'>=]+)[ \t\r\n\f]*=[ \t\r\n\f]*(?:"([^"]*)"|'([^']*)')`)
)

// HTMLAuditUnit is an unchanged contiguous source run in normalized HTML output.
// No interval covers a removed tag, decoded entity, invisible rune or escape.
// Intervals are sorted, disjoint, and use half-open byte offsets.
type HTMLAuditUnit struct{ Start, End int }

// FromChunkForRedactionAudit retains the ordinary HTML decoder's exact bytes
// while proving a bounded subset came from unchanged contiguous source runs.
// Audit-only sentinels distinguish original tokenizer units even when the DOM
// parser merges text across ignored markup. Nothing is written to the source.
func (d *HTML) FromChunkForRedactionAudit(chunk *sources.Chunk) (*DecodableChunk, []HTMLAuditUnit, error) {
	if chunk == nil || len(chunk.Data) == 0 {
		return nil, nil, nil
	}
	if len(chunk.Data) > 1<<20 {
		return nil, nil, errHTMLAudit
	}
	ordinary := d.FromChunkForRedaction(&sources.Chunk{Data: bytes.Clone(chunk.Data)})
	if ordinary == nil {
		return nil, nil, nil
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, nil, errHTMLAudit
	}
	prefix := "|THRA" + hex.EncodeToString(nonce[:]) + "|"
	if bytes.Contains(chunk.Data, []byte(prefix)) || bytes.Contains(ordinary.Data, []byte(prefix)) {
		return nil, nil, errHTMLAudit
	}
	annotated, originals, err := annotateHTMLAudit(chunk.Data, prefix)
	if err != nil {
		return nil, nil, err
	}
	clean, units, err := removeHTMLAuditMarkers(extractHTML(annotated), prefix, originals)
	if err != nil {
		return nil, nil, err
	}
	clean, units, err = normalizeHTMLAuditWhitespace(clean, units)
	if err != nil || !bytes.Equal(clean, ordinary.Data) {
		return nil, nil, errHTMLAudit
	}
	chunk.Data = clean
	return &DecodableChunk{Chunk: chunk, DecoderType: d.Type()}, units, nil
}

func annotateHTMLAudit(input []byte, prefix string) ([]byte, []string, error) {
	var buffer bytes.Buffer
	var originals []string
	var failed bool
	writeRuns := func(data []byte) {
		for i := 0; i < len(data); {
			start := i
			for i < len(data) && data[i] > 32 && data[i] < 127 && data[i] != '&' && data[i] != '%' {
				i++
			}
			if i > start {
				if len(originals) == maxHTMLAuditUnits {
					failed = true
					return
				}
				id := strconv.Itoa(len(originals))
				originals = append(originals, string(data[start:i]))
				buffer.WriteString(prefix + "s" + id + "|")
				buffer.Write(data[start:i])
				buffer.WriteString(prefix + "e" + id + "|")
			}
			if i == len(data) {
				break
			}
			start = i
			if data[i] == '&' {
				i++
				for i < len(data) && (data[i] >= 'A' && data[i] <= 'Z' || data[i] >= 'a' && data[i] <= 'z' || data[i] >= '0' && data[i] <= '9' || data[i] == '#' || data[i] == ';') {
					i++
				}
			} else if data[i] == '%' {
				i += min(3, len(data)-i)
			} else {
				i++
			}
			buffer.Write(data[start:i])
		}
	}
	tokenizer := html.NewTokenizer(bytes.NewReader(input))
	for {
		kind := tokenizer.Next()
		if kind == html.ErrorToken {
			if !errors.Is(tokenizer.Err(), io.EOF) {
				return nil, nil, errHTMLAudit
			}
			break
		}
		raw := tokenizer.Raw()
		switch kind {
		case html.TextToken:
			// Whitespace stays outside sentinels, preserving parser insertion
			// modes and pre/textarea's leading-newline handling.
			writeRuns(raw)
		case html.StartTagToken, html.SelfClosingTagToken:
			nameEnd := 1
			for nameEnd < len(raw) && raw[nameEnd] > 32 && raw[nameEnd] != '/' && raw[nameEnd] != '>' {
				nameEnd++
			}
			namespaced := bytes.Contains(raw[1:nameEnd], []byte(":"))
			start := 0
			for _, match := range htmlAuditQuotedAttributes.FindAllSubmatchIndex(raw, -1) {
				key := strings.ToLower(string(raw[match[2]:match[3]]))
				// Class and parser-structural attributes remain untouched. Only
				// values the ordinary extractor emits need provenance proof.
				if !namespaced && !highSignalAttrs[key] && !strings.HasPrefix(key, "data-") {
					continue
				}
				left, right := match[4], match[5]
				if left < 0 {
					left, right = match[6], match[7]
				}
				buffer.Write(raw[start:left])
				writeRuns(raw[left:right])
				start = right
			}
			buffer.Write(raw[start:])
		case html.CommentToken:
			if bytes.HasPrefix(raw, []byte("<!--")) && bytes.HasSuffix(raw, []byte("-->")) {
				buffer.Write(raw[:4])
				writeRuns(raw[4 : len(raw)-3])
				buffer.Write(raw[len(raw)-3:])
			} else {
				buffer.Write(raw)
			}
		default:
			buffer.Write(raw)
		}
		if failed || buffer.Len() > 1<<20 {
			return nil, nil, errHTMLAudit
		}
	}
	return buffer.Bytes(), originals, nil
}

func removeHTMLAuditMarkers(input []byte, prefix string, originals []string) ([]byte, []HTMLAuditUnit, error) {
	var buffer bytes.Buffer
	var units []HTMLAuditUnit
	open, start, markers := -1, 0, 0
	for cursor := 0; cursor < len(input); {
		index := bytes.Index(input[cursor:], []byte(prefix))
		if index < 0 {
			buffer.Write(input[cursor:])
			break
		}
		index += cursor
		buffer.Write(input[cursor:index])
		left := index + len(prefix)
		end := bytes.IndexByte(input[left:], '|')
		if end < 2 || markers >= 4*maxHTMLAuditUnits {
			return nil, nil, errHTMLAudit
		}
		end += left
		id, err := strconv.Atoi(string(input[left+1 : end]))
		if err != nil || id < 0 || id >= len(originals) {
			return nil, nil, errHTMLAudit
		}
		switch input[left] {
		case 's':
			if open != -1 {
				open = -2 // Nested/reordered regions cannot establish ownership.
			} else {
				open, start = id, buffer.Len()
			}
		case 'e':
			if open == id && bytes.Equal(buffer.Bytes()[start:], []byte(originals[id])) {
				if len(units) == maxHTMLAuditUnits {
					return nil, nil, errHTMLAudit
				}
				units = append(units, HTMLAuditUnit{start, buffer.Len()})
			}
			open = -1
		default:
			return nil, nil, errHTMLAudit
		}
		markers++
		cursor = end + 1
	}
	return buffer.Bytes(), units, nil
}

// Project only retained line ranges through the decoder's existing whitespace
// normalization. Joining newlines have no source-unit ownership.
func normalizeHTMLAuditWhitespace(input []byte, units []HTMLAuditUnit) ([]byte, []HTMLAuditUnit, error) {
	var buffer bytes.Buffer
	var output []HTMLAuditUnit
	cursor, unitIndex, previousBlank := 0, 0, true
	for _, line := range bytes.Split(input, []byte("\n")) {
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			previousBlank = true
			cursor += len(line) + 1
			continue
		}
		if buffer.Len() > 0 {
			buffer.WriteByte('\n')
			if previousBlank {
				buffer.WriteByte('\n')
			}
		}
		left := cursor + bytes.Index(line, trimmed)
		right, base := left+len(trimmed), buffer.Len()
		buffer.Write(trimmed)
		for unitIndex < len(units) && units[unitIndex].End <= left {
			unitIndex++
		}
		for i := unitIndex; i < len(units) && units[i].Start < right; i++ {
			if len(output) == maxHTMLAuditUnits {
				return nil, nil, errHTMLAudit
			}
			start, end := max(left, units[i].Start), min(right, units[i].End)
			if start < end {
				output = append(output, HTMLAuditUnit{base + start - left, base + end - left})
			}
		}
		previousBlank = false
		cursor += len(line) + 1
	}
	return buffer.Bytes(), output, nil
}
