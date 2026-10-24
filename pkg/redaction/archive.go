package redaction

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"io/fs"
	"sort"
	"strings"
)

const (
	maxArchiveEntries = 4096
	maxArchiveDepth   = 5
)

var errArchive = errors.New("archive is unsupported, corrupt, signed or exceeds its work budget; source withheld")

type archiveBudget struct{ expanded, entries, detectorWork int }

type redactionZIP struct {
	*zip.Reader
	localExtras  [][]byte
	reproducible bool
}

// Redact validates archive members in memory before returning any source bytes.
// ZIP/JAR containers retain their exact bytes when no member needs an edit.
func (s *Scanner) Redact(ctx context.Context, input []byte) (output []byte, report Report, err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("redaction component failed; source withheld")
		}
		if err != nil {
			output = nil
		}
	}()
	return s.redactContent(ctx, input, 0, &archiveBudget{})
}

// IsSupportedZIP recognizes a bounded, unambiguous ZIP layout. Members must
// still be read, checked and scanned before the archive can be released.
func IsSupportedZIP(input []byte) bool {
	_, err := openRedactionZIP(input)
	return err == nil
}

// IsZIPContainer also recognizes ZIP trailers behind an unsupported preamble.
// Recognition is deliberately broader than validation, so such containers fail
// closed rather than releasing compressed members through the text scanner.
func IsZIPContainer(input []byte) bool {
	for _, prefix := range []string{"PK\x03\x04", "PK\x05\x06", "PK\x01\x02", "PK\x07\x08", "PK\x06\x06", "PK\x06\x07"} {
		if bytes.HasPrefix(input, []byte(prefix)) {
			return true
		}
	}
	return zipEndRecord(input) >= 0
}

func zipEndRecord(input []byte) int {
	for i := len(input) - 22; i >= max(0, len(input)-22-65535); i-- {
		if bytes.Equal(input[i:i+4], []byte("PK\x05\x06")) && i+22+int(binary.LittleEndian.Uint16(input[i+20:i+22])) <= len(input) {
			return i
		}
	}
	return -1
}

func unsupportedArchive(input []byte) bool {
	for _, prefix := range [][]byte{{0x1f, 0x8b}, []byte("7z\xbc\xaf\x27\x1c"), []byte("Rar!"), []byte("%PDF-"), []byte("BZh"), {0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00}, {0x28, 0xb5, 0x2f, 0xfd}, []byte("!<arch>\n"), {0xed, 0xab, 0xee, 0xdb}} {
		if bytes.HasPrefix(input, prefix) {
			return true
		}
	}
	return len(input) > 262 && string(input[257:262]) == "ustar"
}

func (s *Scanner) redactContent(ctx context.Context, input []byte, depth int, budget *archiveBudget) ([]byte, Report, error) {
	if err := ctx.Err(); err != nil {
		return nil, Report{}, err
	}
	if len(input) > maxViewBytes || unsupportedArchive(input) {
		return nil, Report{}, errArchive
	}
	if !IsZIPContainer(input) {
		return s.redactText(ctx, input, &budget.detectorWork)
	}
	if depth >= maxArchiveDepth {
		return nil, Report{}, errArchive
	}
	reader, err := openRedactionZIP(input)
	if err != nil || len(reader.File) > maxArchiveEntries-budget.entries {
		return nil, Report{}, errArchive
	}
	budget.entries += len(reader.File)
	if err := s.auditZIPMetadata(ctx, budget, []byte(reader.Comment)); err != nil {
		return nil, Report{}, err
	}
	outputs := make([][]byte, len(reader.File))
	changed := false
	signed := bytes.Contains(input, []byte("APK Sig Block 42"))
	var report Report
	for i, member := range reader.File {
		if err := s.auditZIPMetadata(ctx, budget, []byte(member.Name), []byte(member.Comment), member.Extra, reader.localExtras[i]); err != nil {
			return nil, report, err
		}
		if member.Mode()&fs.ModeType != 0 && !member.FileInfo().IsDir() {
			return nil, report, errArchive
		}
		name := strings.ToUpper(strings.ReplaceAll(member.Name, "\\", "/"))
		if signedZIPMember(name) {
			signed = true
		}
		data, err := readZIPMember(ctx, member, min(maxViewBytes, maxAllViewBytes-budget.expanded))
		if err != nil || member.FileInfo().IsDir() && len(data) != 0 {
			return nil, report, errArchive
		}
		budget.expanded += len(data)
		output, part, err := s.redactContent(ctx, data, depth+1, budget)
		if err != nil {
			return nil, report, err
		}
		outputs[i] = output
		report.Detections += part.Detections
		report.Replacements += part.Replacements
		changed = changed || !bytes.Equal(output, data)
	}
	if !changed {
		return bytes.Clone(input), report, nil
	}
	if signed || !reader.reproducible {
		return nil, report, errArchive
	}
	var buffer bytes.Buffer
	writer := zip.NewWriter(&archiveWriter{buffer: &buffer, limit: maxViewBytes})
	if writer.SetComment(reader.Comment) != nil {
		return nil, report, errArchive
	}
	for i, member := range reader.File {
		original, err := readZIPMember(ctx, member, maxViewBytes)
		if err != nil {
			return nil, report, errArchive
		}
		if bytes.Equal(original, outputs[i]) {
			err = writer.Copy(member)
		} else {
			err = writeZIPMember(writer, member, outputs[i])
		}
		if err != nil {
			return nil, report, errArchive
		}
	}
	if writer.Close() != nil {
		return nil, report, errArchive
	}
	output := buffer.Bytes()
	rebuilt, err := openRedactionZIP(output)
	if err != nil || len(rebuilt.File) != len(reader.File) || rebuilt.Comment != reader.Comment {
		return nil, report, errArchive
	}
	for i, member := range rebuilt.File {
		before := reader.File[i]
		if member.Name != before.Name || member.Comment != before.Comment || member.Method != before.Method || member.Flags != before.Flags || member.Mode() != before.Mode() || member.ModifiedDate != before.ModifiedDate || member.ModifiedTime != before.ModifiedTime || !bytes.Equal(member.Extra, before.Extra) {
			return nil, report, errArchive
		}
		data, err := readZIPMember(ctx, member, maxViewBytes)
		if err != nil || !bytes.Equal(data, outputs[i]) {
			return nil, report, errArchive
		}
	}
	return output, report, ctx.Err()
}

type archiveReader struct {
	context context.Context
	reader  io.Reader
}

func (r archiveReader) Read(p []byte) (int, error) {
	if err := r.context.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

func readZIPMember(ctx context.Context, member *zip.File, limit int) ([]byte, error) {
	if limit < 0 || member.UncompressedSize64 > uint64(limit) || member.CompressedSize64 > maxViewBytes {
		return nil, errArchive
	}
	raw, err := member.OpenRaw()
	if err != nil {
		return nil, errArchive
	}
	var reader io.ReadCloser
	var compressed *bytes.Reader
	if member.Method == zip.Deflate {
		data, err := io.ReadAll(io.LimitReader(archiveReader{ctx, raw}, maxViewBytes+1))
		if err != nil || uint64(len(data)) != member.CompressedSize64 {
			return nil, errArchive
		}
		// bytes.Reader implements io.ByteReader. flate consequently consumes
		// exactly the compressed stream, without buffering an ignored tail.
		compressed = bytes.NewReader(data)
		reader = flate.NewReader(compressed)
	} else if member.Method == zip.Store {
		reader = io.NopCloser(raw)
	} else {
		return nil, errArchive
	}
	data, readErr := io.ReadAll(io.LimitReader(archiveReader{ctx, reader}, int64(limit)+1))
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || len(data) > limit || uint64(len(data)) != member.UncompressedSize64 || crc32.ChecksumIEEE(data) != member.CRC32 || compressed != nil && compressed.Len() != 0 {
		return nil, errArchive
	}
	return data, nil
}

func (s *Scanner) auditZIPMetadata(ctx context.Context, budget *archiveBudget, fields ...[]byte) error {
	for _, field := range fields {
		if len(field) == 0 {
			continue
		}
		output, report, err := s.redactText(ctx, field, &budget.detectorWork)
		if err != nil || report.Replacements != 0 || !bytes.Equal(output, field) {
			return errArchive
		}
	}
	return nil
}

func signedZIPMember(name string) bool {
	return strings.HasPrefix(name, "_XMLSIGNATURES/") || name == "APPXSIGNATURE.P7X" || name == "APPXBLOCKMAP.XML" ||
		strings.HasPrefix(name, "META-INF/") && (strings.HasSuffix(name, ".SF") || strings.HasSuffix(name, ".RSA") || strings.HasSuffix(name, ".DSA") || strings.HasSuffix(name, ".EC") || strings.HasSuffix(name, ".P7S") || strings.HasPrefix(name, "META-INF/SIG-") || name == "META-INF/DOCUMENTSIGNATURES.XML" || name == "META-INF/MACROSIGNATURES.XML" || name == "META-INF/PACKAGESIGNATURES.XML" || name == "META-INF/SIGNATURES.XML")
}

type archiveWriter struct {
	buffer *bytes.Buffer
	limit  int
}

func (w *archiveWriter) Write(p []byte) (int, error) {
	if len(p) > w.limit-w.buffer.Len() {
		return 0, errArchive
	}
	return w.buffer.Write(p)
}

func writeZIPMember(writer *zip.Writer, member *zip.File, data []byte) error {
	header := member.FileHeader
	header.Extra = bytes.Clone(header.Extra)
	compressed := data
	if header.Method == zip.Deflate {
		var buffer bytes.Buffer
		compressor, err := flate.NewWriter(&archiveWriter{buffer: &buffer, limit: maxViewBytes}, flate.DefaultCompression)
		if err != nil {
			return errArchive
		}
		if _, err := compressor.Write(data); err != nil {
			_ = compressor.Close()
			return errArchive
		}
		if compressor.Close() != nil {
			return errArchive
		}
		compressed = buffer.Bytes()
	}
	header.CRC32 = crc32.ChecksumIEEE(data)
	header.CompressedSize64 = uint64(len(compressed))
	header.UncompressedSize64 = uint64(len(data))
	out, err := writer.CreateRaw(&header)
	if err != nil {
		return errArchive
	}
	_, err = out.Write(compressed)
	return err
}

// Reject ZIP64, split/encrypted archives, overlapping records, hidden padding
// and unsupported compression before archive/zip allocates its file table.
// The small format subset permits preserving every non-secret logical byte.
func openRedactionZIP(input []byte) (*redactionZIP, error) {
	if len(input) > maxViewBytes || !(bytes.HasPrefix(input, []byte("PK\x03\x04")) || bytes.HasPrefix(input, []byte("PK\x05\x06"))) {
		return nil, errArchive
	}
	end := zipEndRecord(input)
	if end < 0 || end+22+int(binary.LittleEndian.Uint16(input[end+20:end+22])) != len(input) {
		return nil, errArchive
	}
	eocd := input[end:]
	count := int(binary.LittleEndian.Uint16(eocd[10:12]))
	offset := uint64(binary.LittleEndian.Uint32(eocd[16:20]))
	size := uint64(binary.LittleEndian.Uint32(eocd[12:16]))
	if count > maxArchiveEntries || binary.LittleEndian.Uint32(eocd[4:8]) != 0 || int(binary.LittleEndian.Uint16(eocd[8:10])) != count || offset+size != uint64(end) {
		return nil, errArchive
	}
	type extent struct{ start, end int }
	var extents []extent
	var localExtras [][]byte
	reproducible := true
	cursor := int(offset)
	for range count {
		if cursor+46 > end || string(input[cursor:cursor+4]) != "PK\x01\x02" {
			return nil, errArchive
		}
		header := input[cursor : cursor+46]
		nameLen, extraLen, commentLen := int(binary.LittleEndian.Uint16(header[28:30])), int(binary.LittleEndian.Uint16(header[30:32])), int(binary.LittleEndian.Uint16(header[32:34]))
		next := cursor + 46 + nameLen + extraLen + commentLen
		flags, method := binary.LittleEndian.Uint16(header[8:10]), binary.LittleEndian.Uint16(header[10:12])
		compressed, uncompressed := binary.LittleEndian.Uint32(header[20:24]), binary.LittleEndian.Uint32(header[24:28])
		local := uint64(binary.LittleEndian.Uint32(header[42:46]))
		if next > end || flags&^uint16(0x080e) != 0 || method != zip.Store && method != zip.Deflate || binary.LittleEndian.Uint16(header[34:36]) != 0 || compressed == ^uint32(0) || uncompressed == ^uint32(0) || local+30 > offset {
			return nil, errArchive
		}
		localHeader := input[int(local) : int(local)+30]
		localName, localExtra := int(binary.LittleEndian.Uint16(localHeader[26:28])), int(binary.LittleEndian.Uint16(localHeader[28:30]))
		dataStart := int(local) + 30 + localName + localExtra
		dataEnd := uint64(dataStart) + uint64(compressed)
		if string(localHeader[:4]) != "PK\x03\x04" || binary.LittleEndian.Uint16(localHeader[6:8]) != flags || binary.LittleEndian.Uint16(localHeader[8:10]) != method || dataEnd > offset || localName != nameLen || !bytes.Equal(input[int(local)+30:int(local)+30+localName], input[cursor+46:cursor+46+nameLen]) {
			return nil, errArchive
		}
		for _, extra := range [][]byte{input[cursor+46+nameLen : cursor+46+nameLen+extraLen], input[int(local)+30+localName : dataStart]} {
			for len(extra) > 0 {
				if len(extra) < 4 || int(binary.LittleEndian.Uint16(extra[2:4])) > len(extra)-4 {
					return nil, errArchive
				}
				kind := binary.LittleEndian.Uint16(extra[:2])
				if kind == 1 || kind == 0x17 || kind == 0x9901 || kind == 0x7075 || kind == 0x6375 {
					return nil, errArchive
				}
				extra = extra[4+int(binary.LittleEndian.Uint16(extra[2:4])):]
			}
		}
		// archive/zip reconstructs local metadata from central headers. Do not
		// release an edited archive if that would discard distinct metadata.
		if !bytes.Equal(localHeader[4:6], header[6:8]) || !bytes.Equal(localHeader[10:14], header[12:16]) || binary.LittleEndian.Uint16(header[36:38]) != 0 || !bytes.Equal(input[int(local)+30+localName:dataStart], input[cursor+46+nameLen:cursor+46+nameLen+extraLen]) {
			reproducible = false
		}
		blockEnd := int(dataEnd)
		if flags&8 != 0 {
			if blockEnd+4 <= int(offset) && string(input[blockEnd:blockEnd+4]) == "PK\x07\x08" {
				blockEnd += 4
			}
			if blockEnd+12 > int(offset) || !bytes.Equal(input[blockEnd:blockEnd+12], header[16:28]) {
				return nil, errArchive
			}
			blockEnd += 12
		} else if !bytes.Equal(localHeader[14:26], header[16:28]) {
			return nil, errArchive
		}
		extents = append(extents, extent{int(local), blockEnd})
		localExtras = append(localExtras, input[int(local)+30+localName:dataStart])
		cursor = next
	}
	if cursor != end {
		return nil, errArchive
	}
	sort.Slice(extents, func(i, j int) bool { return extents[i].start < extents[j].start })
	last := 0
	for _, block := range extents {
		if block.start != last || block.end < block.start {
			return nil, errArchive
		}
		last = block.end
	}
	if last != int(offset) {
		return nil, errArchive
	}
	reader, err := zip.NewReader(bytes.NewReader(input), int64(len(input)))
	if err != nil || len(reader.File) != count || !safeZIPMembers(reader) {
		return nil, errArchive
	}
	return &redactionZIP{Reader: reader, localExtras: localExtras, reproducible: reproducible}, nil
}

func safeZIPMembers(reader *zip.Reader) bool {
	seen, parents := make(map[string]bool), make(map[string]bool)
	for _, member := range reader.File {
		name := strings.TrimSuffix(member.Name, "/")
		if !fs.ValidPath(name) || strings.ContainsAny(name, "\\:<>\"|?*") || member.Mode()&fs.ModeType != 0 && !member.FileInfo().IsDir() {
			return false
		}
		for _, part := range strings.Split(name, "/") {
			if strings.TrimRight(part, ". ") != part {
				return false
			}
			for _, r := range part {
				if r < 32 || r > 126 {
					return false
				}
			}
		}
		key := strings.ToLower(name)
		if _, duplicate := seen[key]; duplicate || !member.FileInfo().IsDir() && parents[key] {
			return false
		}
		seen[key] = member.FileInfo().IsDir()
		parts := strings.Split(key, "/")
		for i := 1; i < len(parts); i++ {
			parent := strings.Join(parts[:i], "/")
			if directory, exists := seen[parent]; exists && !directory {
				return false
			}
			parents[parent] = true
		}
	}
	return true
}
