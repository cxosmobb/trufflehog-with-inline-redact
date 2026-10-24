package redaction

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"context"
	"encoding/binary"
	"hash/crc32"
	"io"
	"io/fs"
	"testing"
	"time"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
)

const archiveTestSecret = "archiveSyntheticSensitiveCredential9385"

type zipTestMember struct {
	name   string
	data   []byte
	method uint16
	mode   fs.FileMode
}

func zipFixture(t *testing.T, members ...zipTestMember) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	if err := writer.SetComment("retain archive comment"); err != nil {
		t.Fatal(err)
	}
	for _, member := range members {
		header := zip.FileHeader{Name: member.name, Method: member.method, Comment: "retain member comment", Extra: []byte{0xfe, 0xca, 2, 0, 7, 9}, Modified: time.Date(2025, 1, 2, 3, 4, 6, 0, time.UTC)}
		mode := member.mode
		if mode == 0 {
			mode = 0640
		}
		header.SetMode(mode)
		out, err := writer.CreateHeader(&header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := out.Write(member.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return bytes.Clone(buffer.Bytes())
}

func archiveScanner(t *testing.T) *Scanner {
	t.Helper()
	s, err := New([]detectors.Detector{&testDetector{secret: archiveTestSecret, parts: map[string]string{"key": archiveTestSecret}}})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func zipMemberData(t *testing.T, data []byte, index int) []byte {
	t.Helper()
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil || index >= len(reader.File) {
		t.Fatal("invalid test archive")
	}
	output, err := readZIPMember(context.Background(), reader.File[index], maxViewBytes)
	if err != nil {
		t.Fatal(err)
	}
	return output
}

func TestZIPRedactionPreservesExactCleanArchive(t *testing.T) {
	input := zipFixture(t, zipTestMember{"src/main.txt", []byte("unrelated original text"), zip.Deflate, 0750}, zipTestMember{"assets/", nil, zip.Store, fs.ModeDir | 0755})
	before := bytes.Clone(input)
	output, report, err := archiveScanner(t).Redact(context.Background(), input)
	if err != nil || !bytes.Equal(output, input) || !bytes.Equal(before, input) || report.Replacements != 0 {
		t.Fatal("clean ZIP bytes changed or source was mutated")
	}
	if !IsSupportedZIP(input) {
		t.Fatal("valid ZIP was rejected by source routing")
	}
}

func TestZIPRedactionPreservesMembersAndMetadata(t *testing.T) {
	for _, method := range []uint16{zip.Store, zip.Deflate} {
		t.Run(map[uint16]string{zip.Store: "stored", zip.Deflate: "deflated"}[method], func(t *testing.T) {
			input := zipFixture(t, zipTestMember{"src/secret.txt", []byte("prefix token='" + archiveTestSecret + "'; suffix\r\n"), method, 0640}, zipTestMember{"src/unchanged.txt", []byte("unchanged member bytes\x00"), zip.Deflate, 0750})
			before := bytes.Clone(input)
			output, report, err := archiveScanner(t).Redact(context.Background(), input)
			if err != nil || report.Replacements != 1 || !bytes.Equal(input, before) {
				t.Fatal("ZIP redaction failed, changed input, or counted incorrect edits")
			}
			if string(zipMemberData(t, output, 0)) != "prefix token='REDACTED'; suffix\r\n" || string(zipMemberData(t, output, 1)) != "unchanged member bytes\x00" {
				t.Fatal("ZIP edit changed non-sensitive logical bytes")
			}
			oldReader, _ := openRedactionZIP(input)
			newReader, _ := openRedactionZIP(output)
			oldRaw, _ := oldReader.File[1].OpenRaw()
			newRaw, _ := newReader.File[1].OpenRaw()
			oldBytes, _ := io.ReadAll(oldRaw)
			newBytes, _ := io.ReadAll(newRaw)
			if !bytes.Equal(oldBytes, newBytes) || newReader.Comment != oldReader.Comment {
				t.Fatal("unchanged compressed data or archive comment changed")
			}
			for i, member := range oldReader.File {
				rebuilt := newReader.File[i]
				if member.Name != rebuilt.Name || member.Comment != rebuilt.Comment || member.Flags != rebuilt.Flags || member.Method != rebuilt.Method || member.Mode() != rebuilt.Mode() || !bytes.Equal(member.Extra, rebuilt.Extra) || member.ModifiedDate != rebuilt.ModifiedDate || member.ModifiedTime != rebuilt.ModifiedTime {
					t.Fatal("member metadata changed")
				}
			}
			again, second, err := archiveScanner(t).Redact(context.Background(), output)
			if err != nil || !bytes.Equal(again, output) || second.Replacements != 0 {
				t.Fatal("redacted ZIP is not clean and byte-idempotent")
			}
		})
	}
}

func TestZIPRedactionNestedJAR(t *testing.T) {
	inner := zipFixture(t, zipTestMember{"nested.properties", []byte("token='" + archiveTestSecret + "'\n"), zip.Deflate, 0644})
	input := zipFixture(t, zipTestMember{"lib/challenge.jar", inner, zip.Deflate, 0644})
	output, report, err := archiveScanner(t).Redact(context.Background(), input)
	if err != nil || report.Replacements != 1 || string(zipMemberData(t, zipMemberData(t, output, 0), 0)) != "token='REDACTED'\n" {
		t.Fatal("nested JAR was not redacted precisely")
	}
}

func TestZIPRedactionRejectsCorruptOrUnsupportedMembers(t *testing.T) {
	clean := zipFixture(t, zipTestMember{"clean.txt", []byte("keep content"), zip.Store, 0644})
	mutate := func(change func([]byte)) []byte {
		data := bytes.Clone(clean)
		change(data)
		return data
	}
	central := bytes.Index(clean, []byte("PK\x01\x02"))
	corruptCRC := mutate(func(data []byte) {
		reader, _ := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		offset, _ := reader.File[0].DataOffset()
		data[offset] ^= 1
	})
	encrypted := mutate(func(data []byte) { data[6] |= 1; data[central+8] |= 1 })
	method := mutate(func(data []byte) {
		binary.LittleEndian.PutUint16(data[8:10], 99)
		binary.LittleEndian.PutUint16(data[central+10:central+12], 99)
	})
	mismatchedName := mutate(func(data []byte) { data[30] ^= 1 })
	for name, input := range map[string][]byte{
		"CRC": corruptCRC, "encrypted": encrypted, "compression": method, "local name": mismatchedName,
		"truncated": clean[:len(clean)-1], "trailing": append(bytes.Clone(clean), 1),
		"nested unsupported": zipFixture(t, zipTestMember{"inner.gz", []byte{0x1f, 0x8b, 0, 0}, zip.Store, 0644}),
		"orphan directory":   []byte("PK\x01\x02synthetic malformed archive"),
	} {
		t.Run(name, func(t *testing.T) {
			output, _, err := archiveScanner(t).Redact(context.Background(), input)
			if err == nil || output != nil {
				t.Fatal("invalid archive released source despite having no finding")
			}
		})
	}
}

func TestZIPRedactionRejectsUnsafeOrAmbiguousMembers(t *testing.T) {
	for _, name := range []string{"../escape.txt", "/absolute.txt", "C:/drive.txt", "file:stream", "a\\b.txt", "a/../b.txt", "a./b.txt", "a /b.txt", "control\x00.txt", "Σ.txt", "ς.txt", "pipe|name.txt"} {
		t.Run(name, func(t *testing.T) {
			input := zipFixture(t, zipTestMember{name, []byte("ordinary data"), zip.Store, 0644})
			output, _, err := archiveScanner(t).Redact(context.Background(), input)
			if err == nil || output != nil || IsSupportedZIP(input) {
				t.Fatal("unsafe archive path was accepted")
			}
		})
	}
	for name, members := range map[string][]zipTestMember{
		"duplicate":        {{"same.txt", nil, zip.Store, 0644}, {"same.txt", nil, zip.Store, 0644}},
		"case collision":   {{"same.txt", nil, zip.Store, 0644}, {"SAME.TXT", nil, zip.Store, 0644}},
		"file parent":      {{"a", nil, zip.Store, 0644}, {"a/b", nil, zip.Store, 0644}},
		"late file parent": {{"a/b", nil, zip.Store, 0644}, {"a", nil, zip.Store, 0644}},
		"symlink":          {{"link", []byte("target"), zip.Store, fs.ModeSymlink | 0777}},
		"device":           {{"device", nil, zip.Store, fs.ModeDevice | 0600}},
	} {
		t.Run(name, func(t *testing.T) {
			input := zipFixture(t, members...)
			if output, _, err := archiveScanner(t).Redact(context.Background(), input); err == nil || output != nil {
				t.Fatal("ambiguous or special archive member was accepted")
			}
		})
	}
}

func TestZIPRedactionPreservesCleanSignedJARAndWithholdsEdits(t *testing.T) {
	for _, secret := range []string{"ordinary data", archiveTestSecret} {
		input := zipFixture(t, zipTestMember{"META-INF/EXAMPLE.SF", []byte("signature metadata"), zip.Deflate, 0644}, zipTestMember{"config.txt", []byte(secret), zip.Deflate, 0644})
		output, _, err := archiveScanner(t).Redact(context.Background(), input)
		if secret == archiveTestSecret {
			if err == nil || output != nil {
				t.Fatal("edited signed JAR was released with invalid signature")
			}
		} else if err != nil || !bytes.Equal(input, output) {
			t.Fatal("clean signed JAR was not retained byte-identically")
		}
	}
}

func TestZIPRedactionBoundsAndCancellation(t *testing.T) {
	s := archiveScanner(t)
	input := zipFixture(t, zipTestMember{"config.txt", []byte(archiveTestSecret), zip.Deflate, 0644})
	for name, budget := range map[string]archiveBudget{
		"expanded":      {expanded: maxAllViewBytes - 1},
		"entries":       {entries: maxArchiveEntries},
		"detector work": {detectorWork: maxDetectorWorkBytes - 1},
	} {
		t.Run(name, func(t *testing.T) {
			if output, _, err := s.redactContent(context.Background(), input, 0, &budget); err == nil || output != nil {
				t.Fatal("archive exceeded a shared work budget")
			}
		})
	}
	deep := input
	for range maxArchiveDepth {
		deep = zipFixture(t, zipTestMember{"inner.jar", deep, zip.Deflate, 0644})
	}
	if output, _, err := s.Redact(context.Background(), deep); err == nil || output != nil {
		t.Fatal("archive exceeded the recursion bound")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if output, _, err := s.Redact(ctx, input); err == nil || output != nil {
		t.Fatal("canceled archive scan released source")
	}
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	if _, err := writer.CreateRaw(&zip.FileHeader{Name: "oversized.txt", Method: zip.Store, UncompressedSize64: maxViewBytes + 1}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if output, _, err := s.Redact(context.Background(), buffer.Bytes()); err == nil || output != nil {
		t.Fatal("oversized declared member was released")
	}
}

func TestZIPRedactionWithholdsSecretMetadata(t *testing.T) {
	for _, location := range []string{"archive comment", "member name", "member comment", "central extra", "local extra"} {
		t.Run(location, func(t *testing.T) {
			var buffer bytes.Buffer
			writer := zip.NewWriter(&buffer)
			header := zip.FileHeader{Name: "clean.txt", Method: zip.Store}
			switch location {
			case "archive comment":
				_ = writer.SetComment(archiveTestSecret)
			case "member name":
				header.Name = archiveTestSecret + ".txt"
			case "member comment":
				header.Comment = archiveTestSecret
			default:
				header.Extra = append([]byte{0xfe, 0xca, byte(len(archiveTestSecret)), 0}, []byte(archiveTestSecret)...)
			}
			out, err := writer.CreateHeader(&header)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.WriteString(out, "ordinary body")
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			input := bytes.Clone(buffer.Bytes())
			if location == "central extra" {
				start := 30 + len(header.Name) + 4
				copy(input[start:start+len(archiveTestSecret)], bytes.Repeat([]byte("x"), len(archiveTestSecret)))
			} else if location == "local extra" {
				start := bytes.Index(input, []byte("PK\x01\x02")) + 46 + len(header.Name) + 4
				copy(input[start:start+len(archiveTestSecret)], bytes.Repeat([]byte("x"), len(archiveTestSecret)))
			}
			if output, _, err := archiveScanner(t).Redact(context.Background(), input); err == nil || output != nil {
				t.Fatal("secret-bearing ZIP metadata was released")
			}
		})
	}
}

func TestZIPRedactionRejectsIgnoredDeflateTail(t *testing.T) {
	body := []byte("ordinary member content")
	var compressed bytes.Buffer
	compressor, err := flate.NewWriter(&compressed, flate.DefaultCompression)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = compressor.Write(body)
	if err := compressor.Close(); err != nil {
		t.Fatal(err)
	}
	compressed.WriteString(archiveTestSecret)
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	header := zip.FileHeader{Name: "clean.txt", Method: zip.Deflate, CRC32: crc32.ChecksumIEEE(body), CompressedSize64: uint64(compressed.Len()), UncompressedSize64: uint64(len(body))}
	out, err := writer.CreateRaw(&header)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = out.Write(compressed.Bytes())
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	// The standard reader accepts this ZIP but ignores the secret-bearing tail.
	reader, err := zip.NewReader(bytes.NewReader(buffer.Bytes()), int64(buffer.Len()))
	if err != nil {
		t.Fatal(err)
	}
	member, err := reader.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := io.ReadAll(member)
	_ = member.Close()
	if err != nil || !bytes.Equal(decoded, body) {
		t.Fatal("ignored-tail fixture did not reproduce the standard-reader gap")
	}
	if output, _, err := archiveScanner(t).Redact(context.Background(), buffer.Bytes()); err == nil || output != nil {
		t.Fatal("ignored compressed tail was released")
	}
}

func TestZIPSignatureAndIntegrityMarkers(t *testing.T) {
	for _, name := range []string{"META-INF/EXAMPLE.SF", "META-INF/EXAMPLE.RSA", "_XMLSIGNATURES/ORIGIN.SIGS", "META-INF/DOCUMENTSIGNATURES.XML", "META-INF/MACROSIGNATURES.XML", "META-INF/PACKAGESIGNATURES.XML", "META-INF/SIGNATURES.XML", "META-INF/SIGNATURES.P7S", "APPXSIGNATURE.P7X", "APPXBLOCKMAP.XML"} {
		if !signedZIPMember(name) {
			t.Fatal("known ZIP signature or integrity metadata was not protected")
		}
	}
}

func TestZIPRedactionWithholdsLossyLocalMetadataRewrite(t *testing.T) {
	for _, secret := range []string{"ordinary data", archiveTestSecret} {
		input := zipFixture(t, zipTestMember{"unchanged.txt", []byte("keep body"), zip.Store, 0644}, zipTestMember{"config.txt", []byte(secret), zip.Store, 0644})
		// The valid local custom extra differs from its central-directory copy.
		start := 30 + len("unchanged.txt") + 4
		input[start] ^= 1
		output, _, err := archiveScanner(t).Redact(context.Background(), input)
		if secret == archiveTestSecret {
			if err == nil || output != nil {
				t.Fatal("edited ZIP discarded distinct original local metadata")
			}
		} else if err != nil || !bytes.Equal(input, output) {
			t.Fatal("clean ZIP with distinct local metadata did not retain exact bytes")
		}
	}
}

func TestZIPRedactionRejectsAlternateUnicodeMetadata(t *testing.T) {
	for _, kind := range []uint16{0x7075, 0x6375} {
		input := zipFixture(t, zipTestMember{"safe.txt", []byte("ordinary data"), zip.Store, 0644})
		central := bytes.Index(input, []byte("PK\x01\x02"))
		binary.LittleEndian.PutUint16(input[30+len("safe.txt"):], kind)
		binary.LittleEndian.PutUint16(input[central+46+len("safe.txt"):], kind)
		if output, _, err := archiveScanner(t).Redact(context.Background(), input); err == nil || output != nil {
			t.Fatal("ambiguous alternate ZIP path or comment encoding was accepted")
		}
	}
}

func TestZIPRedactionRejectsPrefixedContainer(t *testing.T) {
	archive := zipFixture(t, zipTestMember{"secret.txt", []byte(archiveTestSecret), zip.Deflate, 0644})
	for _, suffix := range []string{"", "ignored trailer"} {
		input := append(append([]byte("synthetic executable preamble\n"), archive...), []byte(suffix)...)
		// Standard ZIP processing accepts the preamble and optional trailer.
		reader, err := zip.NewReader(bytes.NewReader(input), int64(len(input)))
		if err != nil || len(reader.File) != 1 {
			t.Fatal("prefixed ZIP fixture did not reproduce the native format")
		}
		if !IsZIPContainer(input) || IsSupportedZIP(input) {
			t.Fatal("unsupported prefixed ZIP was misclassified as plain source")
		}
		if output, _, err := archiveScanner(t).Redact(context.Background(), input); err == nil || output != nil {
			t.Fatal("prefixed ZIP released an unscanned compressed credential")
		}
	}
}
