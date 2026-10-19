package redaction

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"html"
	"sort"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// projectedText keeps transformations separate from detection. Every edit is
// projected through its parents before it can change the original input.
type projectedText struct {
	data    []byte
	project func([]edit) ([]edit, error)
	pieces  int
	err     error
}

// Source text is untrusted. Bound the decoded representations and their
// provenance, including for callers that use the library without the CLI.
const (
	maxViewBytes     = 32 << 20
	maxAllViewBytes  = 128 << 20
	maxViewPieces    = 65536
	maxAllViewPieces = 262144
)

type textCodec uint8

const (
	codecLiteral textCodec = iota
	codecUTF16LE
	codecUTF16BE
)

type textPiece struct {
	outStart, outEnd int
	inStart, inEnd   int
	codec            textCodec
	// stride is the source bytes per decoded byte for runs of independently
	// mapped ASCII characters. Zero denotes one indivisible encoded rune.
	stride int
}

// buildViews deliberately retains source offsets instead of searching the
// original input for a decoded result. Repeated secrets and encoded context
// therefore remain distinguishable. Two rounds also cover common compositions
// such as percent-encoded HTML entities and base64 inside UTF-16 text.
func buildViews(input []byte) ([]view, error) {
	if len(input) > maxViewBytes {
		return nil, fmt.Errorf("source exceeds decoded view budget")
	}
	plain := projectedText{data: input, project: func(edits []edit) ([]edit, error) {
		if err := validateViewEdits(input, edits); err != nil {
			return nil, err
		}
		return edits, nil
	}}
	texts := []projectedText{plain}
	if decoded, ok := decodeUTF16Text(plain); ok {
		if decoded.err != nil {
			return nil, decoded.err
		}
		texts = append(texts, decoded)
	} else {
		for _, codec := range []textCodec{codecUTF16LE, codecUTF16BE} {
			if decoded, ok := decodeMixedUTF16Text(plain, codec); ok {
				if decoded.err != nil {
					return nil, decoded.err
				}
				texts = append(texts, decoded)
			}
		}
	}
	// Deduplication is by decoded bytes. Each retained view still has an exact
	// mapping for every occurrence in that view.
	seen := make(map[string]bool, 16)
	allBytes, allPieces := 0, 0
	for _, text := range texts {
		allBytes += len(text.data)
		allPieces += text.pieces
		seen[string(text.data)] = true
	}
	start := 0
	for round := 0; round < 2; round++ {
		end := len(texts)
		for _, parent := range texts[start:end] {
			for _, decode := range []func(projectedText) (projectedText, bool){decodeEscapedText, decodeBase64Text} {
				child, changed := decode(parent)
				if child.err != nil {
					return nil, child.err
				}
				if changed && !seen[string(child.data)] {
					if len(child.data) > maxAllViewBytes-allBytes || child.pieces > maxAllViewPieces-allPieces {
						return nil, fmt.Errorf("source exceeds cumulative decoded view budget")
					}
					allBytes += len(child.data)
					allPieces += child.pieces
					seen[string(child.data)] = true
					texts = append(texts, child)
				}
			}
		}
		start = end
	}
	views := make([]view, 0, len(texts))
	for _, text := range texts {
		text := text
		views = append(views, view{data: text.data, apply: func(spans []span) ([]edit, error) {
			merged, err := mergeViewSpans(len(text.data), spans)
			if err != nil {
				return nil, err
			}
			edits := make([]edit, 0, len(merged))
			for _, sensitive := range merged {
				edits = append(edits, edit{start: sensitive.start, end: sensitive.end, replacement: []byte("REDACTED")})
			}
			return text.project(edits)
		}})
	}
	return views, nil
}

func mergeViewSpans(length int, spans []span) ([]span, error) {
	spans = append([]span(nil), spans...)
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	merged := make([]span, 0, len(spans))
	for _, current := range spans {
		if current.start < 0 || current.end <= current.start || current.end > length {
			return nil, fmt.Errorf("redaction span outside decoded input")
		}
		if len(merged) > 0 && current.start < merged[len(merged)-1].end {
			if current.end > merged[len(merged)-1].end {
				merged[len(merged)-1].end = current.end
			}
		} else {
			merged = append(merged, current)
		}
	}
	return merged, nil
}

func validateViewEdits(data []byte, edits []edit) error {
	last := 0
	for _, change := range edits {
		if change.start < last || change.end <= change.start || change.end > len(data) {
			return fmt.Errorf("invalid or overlapping decoded redaction edits")
		}
		last = change.end
	}
	return nil
}

func applyViewEdits(data []byte, edits []edit) ([]byte, error) {
	if err := validateViewEdits(data, edits); err != nil {
		return nil, err
	}
	var output bytes.Buffer
	start := 0
	for _, change := range edits {
		output.Write(data[start:change.start])
		output.Write(change.replacement)
		start = change.end
	}
	output.Write(data[start:])
	return output.Bytes(), nil
}

func mappedText(parent projectedText, data []byte, pieces []textPiece) projectedText {
	return projectedText{data: data, pieces: len(pieces), project: func(edits []edit) ([]edit, error) {
		if err := validateViewEdits(data, edits); err != nil {
			return nil, err
		}
		mapped := make([]edit, 0, len(edits))
		for _, change := range edits {
			first := sort.Search(len(pieces), func(i int) bool { return pieces[i].outEnd > change.start })
			last := sort.Search(len(pieces), func(i int) bool { return pieces[i].outEnd >= change.end })
			if first == len(pieces) || last == len(pieces) {
				return nil, fmt.Errorf("redaction has no source mapping")
			}
			startPiece, endPiece := pieces[first], pieces[last]
			start, end := startPiece.inStart, endPiece.inEnd
			if startPiece.stride > 0 {
				start += (change.start - startPiece.outStart) * startPiece.stride
			} else if change.start != startPiece.outStart {
				return nil, fmt.Errorf("redaction cuts through an encoded character")
			}
			if endPiece.stride > 0 {
				end = endPiece.inStart + (change.end-endPiece.outStart)*endPiece.stride
			} else if change.end != endPiece.outEnd {
				return nil, fmt.Errorf("redaction cuts through an encoded character")
			}
			codec := startPiece.codec
			mixed := false
			for _, piece := range pieces[first : last+1] {
				if piece.codec != codec {
					mixed = true
				}
			}
			if mixed {
				// A non-BOM ASCII run can be shifted one byte and appear to
				// have the opposite byte order. Accept it only when the exact
				// source code units, including the bordering NUL, reproduce
				// the complete detected bytes. This also makes both views
				// project to the same source interval and marker encoding.
				var ok bool
				start, end, codec, ok = recoverUTF16Interval(parent.data, start, end, data[change.start:change.end])
				if !ok {
					return nil, fmt.Errorf("redaction crosses text encodings")
				}
			}
			mapped = append(mapped, edit{start: start, end: end, replacement: encodeTextReplacement(change.replacement, codec)})
		}
		return parent.project(mapped)
	}}
}

func recoverUTF16Interval(input []byte, start, end int, decoded []byte) (int, int, textCodec, bool) {
	for _, left := range []int{start, start - 1} {
		for _, right := range []int{end, end + 1} {
			if left < 0 || right > len(input) || right-left != len(decoded)*2 {
				continue
			}
			for _, codec := range []textCodec{codecUTF16LE, codecUTF16BE} {
				matches := true
				for i, expected := range decoded {
					if expected == 0 || utf16ASCIIByte(input[left+i*2:left+i*2+2], codec) != expected {
						matches = false
						break
					}
				}
				if matches {
					return left, right, codec, true
				}
			}
		}
	}
	return 0, 0, codecLiteral, false
}

func encodeTextReplacement(data []byte, codec textCodec) []byte {
	if codec == codecLiteral {
		return bytes.Clone(data)
	}
	var order binary.ByteOrder = binary.LittleEndian
	if codec == codecUTF16BE {
		order = binary.BigEndian
	}
	units := utf16.Encode([]rune(string(data)))
	output := make([]byte, len(units)*2)
	for i, unit := range units {
		order.PutUint16(output[i*2:], unit)
	}
	return output
}

func appendTextPiece(data *[]byte, pieces *[]textPiece, decoded []byte, start, end int, codec textCodec, stride int) error {
	if len(decoded) == 0 {
		return nil
	}
	if len(decoded) > maxViewBytes-len(*data) {
		return fmt.Errorf("source exceeds decoded view budget")
	}
	outStart := len(*data)
	if stride > 0 && len(*pieces) > 0 {
		last := &(*pieces)[len(*pieces)-1]
		if last.stride == stride && last.codec == codec && last.inEnd == start {
			*data = append(*data, decoded...)
			last.inEnd, last.outEnd = end, len(*data)
			return nil
		}
	}
	if len(*pieces) == maxViewPieces {
		return fmt.Errorf("source exceeds provenance mapping budget")
	}
	*data = append(*data, decoded...)
	*pieces = append(*pieces, textPiece{outStart: outStart, outEnd: len(*data), inStart: start, inEnd: end, codec: codec, stride: stride})
	return nil
}

func decodeUTF16Text(parent projectedText) (projectedText, bool) {
	input := parent.data
	if len(input) < 2 || len(input)%2 != 0 {
		return projectedText{}, false
	}
	codec := codecLiteral
	start := 2
	if input[0] == 0xff && input[1] == 0xfe {
		codec = codecUTF16LE
	} else if input[0] == 0xfe && input[1] == 0xff {
		codec = codecUTF16BE
	} else if len(input) >= 8 {
		// If every pair covers the entire source with printable ASCII and
		// NUL, byte order and alignment are unambiguous without a BOM.
		// Retain only that complete view: an opposite-endian run shifted
		// by one byte would produce conflicting interior secret offsets.
		for _, candidate := range []textCodec{codecUTF16LE, codecUTF16BE} {
			complete := true
			for i := 0; i < len(input); i += 2 {
				if utf16ASCIIByte(input[i:i+2], candidate) == 0 {
					complete = false
					break
				}
			}
			if complete {
				codec, start = candidate, 0
				break
			}
		}
	}
	if codec == codecLiteral {
		return projectedText{}, false
	}
	var order binary.ByteOrder = binary.LittleEndian
	if codec == codecUTF16BE {
		order = binary.BigEndian
	}
	var output []byte
	var pieces []textPiece
	for i := start; i < len(input); {
		start := i
		unit := order.Uint16(input[i:])
		i += 2
		r := rune(unit)
		if unit >= 0xd800 && unit <= 0xdbff {
			if i == len(input) {
				return projectedText{}, false
			}
			second := order.Uint16(input[i:])
			if second < 0xdc00 || second > 0xdfff {
				return projectedText{}, false
			}
			r = utf16.DecodeRune(rune(unit), rune(second))
			i += 2
		} else if unit >= 0xdc00 && unit <= 0xdfff {
			return projectedText{}, false
		}
		stride := 0
		if r < utf8.RuneSelf {
			stride = i - start
		}
		if err := appendTextPiece(&output, &pieces, []byte(string(r)), start, i, codec, stride); err != nil {
			return projectedText{err: err}, true
		}
	}
	return mappedText(parent, output, pieces), true
}

// Without a BOM, only alternating printable ASCII/NUL runs are decoded.
// Other bytes retain their own offsets instead of being discarded as in an
// ASCII projection, which could join unrelated source text into a secret.
func decodeMixedUTF16Text(parent projectedText, codec textCodec) (projectedText, bool) {
	input := parent.data
	var output []byte
	var pieces []textPiece
	changed := false
	for i := 0; i < len(input); {
		end := i
		for end+1 < len(input) && utf16ASCIIByte(input[end:end+2], codec) != 0 {
			end += 2
		}
		if end-i >= 8 {
			changed = true
			for ; i < end; i += 2 {
				if err := appendTextPiece(&output, &pieces, []byte{utf16ASCIIByte(input[i:i+2], codec)}, i, i+2, codec, 2); err != nil {
					return projectedText{err: err}, true
				}
			}
		} else {
			if err := appendTextPiece(&output, &pieces, input[i:i+1], i, i+1, codecLiteral, 1); err != nil {
				return projectedText{err: err}, true
			}
			i++
		}
	}
	if !changed {
		return projectedText{}, false
	}
	return mappedText(parent, output, pieces), true
}

func utf16ASCIIByte(pair []byte, codec textCodec) byte {
	value, zero := pair[0], pair[1]
	if codec == codecUTF16BE {
		value, zero = zero, value
	}
	if zero == 0 && (value >= 32 && value <= 126 || value == '\n' || value == '\r' || value == '\t') {
		return value
	}
	return 0
}

func decodeEscapedText(parent projectedText) (projectedText, bool) {
	input := parent.data
	var output []byte
	var pieces []textPiece
	changed := false
	for i := 0; i < len(input); {
		decoded, end, next := decodeTextEscape(input, i)
		if end > i {
			stride := 0
			if len(decoded) == 1 {
				stride = end - i
			}
			if err := appendTextPiece(&output, &pieces, decoded, i, end, codecLiteral, stride); err != nil {
				return projectedText{err: err}, true
			}
			i = next
			changed = true
		} else {
			if err := appendTextPiece(&output, &pieces, input[i:i+1], i, i+1, codecLiteral, 1); err != nil {
				return projectedText{err: err}, true
			}
			i++
		}
	}
	if !changed {
		return projectedText{}, false
	}
	return mappedText(parent, output, pieces), true
}

// end is the end of the source representation; next can additionally skip a
// CSS/code-point separator. Excluding the final separator from the source
// interval preserves punctuation or whitespace following the secret.
func decodeTextEscape(input []byte, start int) (decoded []byte, end, next int) {
	i := start
	if input[i] == '%' {
		if i+6 <= len(input) && input[i+1] == 'u' {
			return decodeHexRune(input, start, i+2, i+6, i+6, i+6)
		}
		if i+3 <= len(input) {
			if value, ok := parseHex(input[i+1 : i+3]); ok {
				return []byte{byte(value)}, i + 3, i + 3
			}
		}
	}
	if input[i] == '&' {
		for j := i + 1; j < len(input) && j-i <= 40; j++ {
			if input[j] == ';' {
				raw := string(input[i : j+1])
				value := html.UnescapeString(raw)
				if value != raw {
					return []byte(value), j + 1, j + 1
				}
				break
			}
			if !(input[j] == '#' || input[j] >= '0' && input[j] <= '9' || input[j] >= 'a' && input[j] <= 'z' || input[j] >= 'A' && input[j] <= 'Z') {
				break
			}
		}
	}
	if input[i] == 'U' && i+6 <= len(input) && input[i+1] == '+' && (i == 0 || !escapeWordByte(input[i-1])) {
		next = i + 6
		if next < len(input) && input[next] == ' ' {
			next++
		}
		return decodeHexRune(input, start, i+2, i+6, i+6, next)
	}
	if input[i] != '\\' {
		return nil, 0, 0
	}
	i++
	if i < len(input) && input[i] == '\\' {
		i++
	}
	if i == len(input) {
		return nil, 0, 0
	}
	if input[i] == 'U' && i+9 <= len(input) {
		if value, end, next := decodeHexRune(input, start, i+1, i+9, i+9, i+9); end > 0 {
			return value, end, next
		}
	}
	if (input[i] == 'u' || input[i] == 'x') && i+1 < len(input) && input[i+1] == '{' {
		for j := i + 2; j < len(input) && j <= i+8; j++ {
			if input[j] == '}' {
				return decodeHexRune(input, start, i+2, j, j+1, j+1)
			}
		}
	}
	if (input[i] == 'u' || input[i] == 'U') && i+5 <= len(input) {
		return decodeHexRune(input, start, i+1, i+5, i+5, i+5)
	}
	// CSS hexadecimal escapes terminate at whitespace or a non-hex byte.
	end = i
	for end < len(input) && end-i < 6 && isEscapeHex(input[end]) {
		end++
	}
	if end > i && (end == len(input) || escapeWhitespace(input[end]) || input[end] == '\\') {
		next = end
		if next < len(input) && escapeWhitespace(input[next]) {
			next++
		}
		return decodeHexRune(input, start, i, end, end, next)
	}
	return nil, 0, 0
}

func decodeHexRune(input []byte, start, hexStart, hexEnd, end, next int) ([]byte, int, int) {
	value, ok := parseHex(input[hexStart:hexEnd])
	if !ok || !utf8.ValidRune(rune(value)) {
		return nil, 0, 0
	}
	return []byte(string(rune(value))), end, next
}

func parseHex(input []byte) (uint32, bool) {
	if len(input) == 0 {
		return 0, false
	}
	for _, value := range input {
		if !isEscapeHex(value) {
			return 0, false
		}
	}
	value, err := strconv.ParseUint(string(input), 16, 32)
	return uint32(value), err == nil
}

func isEscapeHex(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'a' && value <= 'f' || value >= 'A' && value <= 'F'
}

func escapeWordByte(value byte) bool {
	return value == '_' || value >= '0' && value <= '9' || value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'
}

func escapeWhitespace(value byte) bool {
	return value == ' ' || value == '\n' || value == '\r' || value == '\t' || value == '\f'
}

type base64Piece struct {
	outStart, outEnd int
	inStart, inEnd   int
	decoded          []byte
	encoding         *base64.Encoding
}

func decodeBase64Text(parent projectedText) (projectedText, bool) {
	input := parent.data
	var output []byte
	var blobs []base64Piece
	last := 0
	for i := 0; i < len(input); {
		if !base64Byte(input[i]) {
			i++
			continue
		}
		start := i
		for i < len(input) && base64Byte(input[i]) {
			i++
		}
		end := i
		if end-start <= 20 {
			continue
		}
		// Follow upstream's handling of key=value and leading delimiters.
		for start < end && bytes.IndexByte([]byte("+/-_="), input[start]) >= 0 {
			start++
		}
		trimmedEnd := end
		for trimmedEnd > start && bytes.IndexByte([]byte("+/-_="), input[trimmedEnd-1]) >= 0 {
			trimmedEnd--
		}
		if equals := bytes.IndexByte(input[start:trimmedEnd], '='); equals >= 0 {
			start += equals + 1
		}
		var decoded []byte
		var selected *base64.Encoding
		for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawURLEncoding, base64.RawStdEncoding, base64.URLEncoding} {
			candidate, err := encoding.DecodeString(string(input[start:end]))
			if err == nil && len(candidate) > 0 && asciiViewBytes(candidate) {
				decoded, selected = candidate, encoding
				break
			}
		}
		if selected == nil {
			continue
		}
		if len(blobs) == maxViewPieces {
			return projectedText{err: fmt.Errorf("source exceeds base64 provenance budget")}, true
		}
		output = append(output, input[last:start]...)
		outStart := len(output)
		output = append(output, decoded...)
		blobs = append(blobs, base64Piece{outStart: outStart, outEnd: len(output), inStart: start, inEnd: end, decoded: decoded, encoding: selected})
		last = end
	}
	if len(blobs) == 0 {
		return projectedText{}, false
	}
	output = append(output, input[last:]...)
	return projectedText{data: output, pieces: len(blobs), project: func(edits []edit) ([]edit, error) {
		if err := validateViewEdits(output, edits); err != nil {
			return nil, err
		}
		mapped := make([]edit, 0, len(edits))
		inside := make([][]edit, len(blobs))
		for _, change := range edits {
			index := sort.Search(len(blobs), func(i int) bool { return blobs[i].outEnd > change.start })
			if index < len(blobs) && change.end > blobs[index].outStart {
				blob := blobs[index]
				if change.start < blob.outStart || change.end > blob.outEnd {
					return nil, fmt.Errorf("redaction crosses a base64 boundary")
				}
				inside[index] = append(inside[index], edit{start: change.start - blob.outStart, end: change.end - blob.outStart, replacement: change.replacement})
				continue
			}
			shift := 0
			if index > 0 {
				previous := blobs[index-1]
				shift = previous.inEnd - previous.outEnd
			}
			mapped = append(mapped, edit{start: change.start + shift, end: change.end + shift, replacement: change.replacement})
		}
		for i, changes := range inside {
			if len(changes) == 0 {
				continue
			}
			blob := blobs[i]
			redacted, err := applyViewEdits(blob.decoded, changes)
			if err != nil {
				return nil, err
			}
			mapped = append(mapped, edit{start: blob.inStart, end: blob.inEnd, replacement: []byte(blob.encoding.EncodeToString(redacted))})
		}
		sort.Slice(mapped, func(i, j int) bool { return mapped[i].start < mapped[j].start })
		return parent.project(mapped)
	}}, true
}

func base64Byte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || value == '+' || value == '/' || value == '-' || value == '_' || value == '='
}

func asciiViewBytes(data []byte) bool {
	for _, value := range data {
		if value > 127 {
			return false
		}
	}
	return true
}
