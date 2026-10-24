package redaction

import (
	"bytes"
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/decoders"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/box"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
)

func elfTestBinary(payload []byte, wide bool, order binary.ByteOrder) []byte {
	header, entry := 52, 32
	if wide {
		header, entry = 64, 56
	}
	input := make([]byte, header+entry+len(payload))
	copy(input, "\x7fELF")
	input[4], input[5], input[6] = 1, 1, 1
	if wide {
		input[4] = 2
	}
	if order == binary.BigEndian {
		input[5] = 2
	}
	order.PutUint16(input[16:18], 2)
	order.PutUint16(input[18:20], 62)
	order.PutUint32(input[20:24], 1)
	if wide {
		order.PutUint64(input[32:40], uint64(header))
		order.PutUint16(input[52:54], uint16(header))
		order.PutUint16(input[54:56], uint16(entry))
		order.PutUint16(input[56:58], 1)
		order.PutUint64(input[header+32:header+40], uint64(len(input)))
		order.PutUint64(input[header+40:header+48], uint64(len(input)))
	} else {
		order.PutUint32(input[28:32], uint32(header))
		order.PutUint16(input[40:42], uint16(header))
		order.PutUint16(input[42:44], uint16(entry))
		order.PutUint16(input[44:46], 1)
		order.PutUint32(input[header+16:header+20], uint32(len(input)))
		order.PutUint32(input[header+20:header+24], uint32(len(input)))
	}
	order.PutUint32(input[header:header+4], 1)
	copy(input[header+entry:], payload)
	return input
}

func peTestBinary(payload []byte, wide bool) []byte {
	optional := 96
	if wide {
		optional = 112
	}
	table := 64 + 24 + optional
	input := make([]byte, table+40+len(payload))
	copy(input, "MZ")
	binary.LittleEndian.PutUint32(input[60:64], 64)
	copy(input[64:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(input[68:70], 0x14c)
	binary.LittleEndian.PutUint16(input[70:72], 1)
	binary.LittleEndian.PutUint16(input[84:86], uint16(optional))
	binary.LittleEndian.PutUint16(input[86:88], 2)
	binary.LittleEndian.PutUint16(input[88:90], 0x10b)
	if wide {
		binary.LittleEndian.PutUint16(input[68:70], 0x8664)
		binary.LittleEndian.PutUint16(input[88:90], 0x20b)
	}
	copy(input[table:table+8], ".data")
	binary.LittleEndian.PutUint32(input[table+16:table+20], uint32(len(payload)))
	binary.LittleEndian.PutUint32(input[table+20:table+24], uint32(table+40))
	copy(input[table+40:], payload)
	return input
}

func machoTestBinary(payload []byte, wide bool, order binary.ByteOrder) []byte {
	header, command := 28, 56
	magic, cpu, kind := uint32(0xfeedface), uint32(7), uint32(1)
	if wide {
		header, command = 32, 72
		magic, cpu, kind = 0xfeedfacf, 0x01000007, 0x19
	}
	input := make([]byte, header+command+len(payload))
	order.PutUint32(input[:4], magic)
	order.PutUint32(input[4:8], cpu)
	order.PutUint32(input[12:16], 2)
	order.PutUint32(input[16:20], 1)
	order.PutUint32(input[20:24], uint32(command))
	order.PutUint32(input[header:header+4], kind)
	order.PutUint32(input[header+4:header+8], uint32(command))
	copy(input[header+command:], payload)
	return input
}

func TestCompiledBinaryHeaderRecognition(t *testing.T) {
	payload := []byte("synthetic compiled string payload")
	for _, input := range [][]byte{
		elfTestBinary(payload, false, binary.LittleEndian), elfTestBinary(payload, false, binary.BigEndian),
		elfTestBinary(payload, true, binary.LittleEndian), elfTestBinary(payload, true, binary.BigEndian),
		peTestBinary(payload, false), peTestBinary(payload, true),
		machoTestBinary(payload, false, binary.LittleEndian), machoTestBinary(payload, false, binary.BigEndian),
		machoTestBinary(payload, true, binary.LittleEndian), machoTestBinary(payload, true, binary.BigEndian),
	} {
		if !compiledBinary(input) {
			t.Fatal("supported compiled format was not recognized")
		}
	}
	badELF := elfTestBinary(payload, true, binary.LittleEndian)
	binary.LittleEndian.PutUint64(badELF[32:40], uint64(len(badELF)+1))
	badPE := peTestBinary(payload, true)
	binary.LittleEndian.PutUint32(badPE[60:64], ^uint32(0))
	badMachO := machoTestBinary(payload, true, binary.LittleEndian)
	binary.LittleEndian.PutUint32(badMachO[36:40], ^uint32(0))
	for _, input := range [][]byte{
		[]byte("ordinary source text"), []byte("MZ source text"), []byte("\x7fELF"),
		{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 1}, // Java class / fat Mach-O is excluded.
		{0xff, 0xfe, 'p', 0, 'a', 0, 's', 0}, // Ordinary UTF-16 source is unchanged.
		badELF, badPE, badMachO,
	} {
		if compiledBinary(input) {
			t.Fatal("text, unsupported or malformed format was treated as compiled")
		}
	}
}

func TestCompiledBinaryRedactionPreventsBoxContextCascade(t *testing.T) {
	const secret = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
	const public = "abcdefghijklmnopqrstuvwxyz012345"
	payload := []byte("box " + secret + strings.Repeat(".", 13) + public + " keep\x00")
	for name, input := range map[string][]byte{
		"ELF":   elfTestBinary(payload, true, binary.LittleEndian),
		"PE":    peTestBinary(payload, true),
		"MachO": machoTestBinary(payload, true, binary.LittleEndian),
	} {
		t.Run(name, func(t *testing.T) {
			d := &box.Scanner{}
			before, err := d.FromData(context.Background(), false, input)
			if err != nil || len(before) != 1 || before[0].SecretParts["key"] != secret {
				t.Fatal("synthetic binary did not detect only the original credential")
			}
			start := bytes.Index(input, []byte(secret))
			shortened := append(bytes.Clone(input[:start]), []byte(Marker)...)
			shortened = append(shortened, input[start+len(secret):]...)
			promoted, err := d.FromData(context.Background(), false, shortened)
			if err != nil || len(promoted) != 1 || promoted[0].SecretParts["key"] != public {
				t.Fatal("fixture did not reproduce context-shrink false detection")
			}
			s, _ := New([]detectors.Detector{d})
			output, report, err := s.Redact(context.Background(), input)
			if err != nil || report.Replacements != 1 || len(output) != len(input) {
				t.Fatal("compiled redaction failed or shifted file offsets")
			}
			want := bytes.Clone(input)
			copy(want[start:start+len(secret)], bytes.Repeat([]byte{' '}, len(secret)))
			copy(want[start:start+len(secret)], Marker)
			if !bytes.Equal(output, want) || !bytes.Contains(output, []byte(public)) {
				t.Fatal("binary redaction changed bytes outside the original sensitive extent")
			}
			remaining, err := d.FromData(context.Background(), false, output)
			if err != nil || len(remaining) != 0 {
				t.Fatal("fixed-width redaction left or introduced a Box candidate")
			}
			again, second, err := s.Redact(context.Background(), output)
			if err != nil || second.Replacements != 0 || !bytes.Equal(again, output) {
				t.Fatal("compiled redaction was not clean and byte-idempotent")
			}
		})
	}
}

func TestCompiledBinaryShortExtentWithholdsSource(t *testing.T) {
	input := elfTestBinary([]byte("password=x"), true, binary.LittleEndian)
	output, _, err := applyEdits(input, []edit{{len(input) - 1, len(input), []byte(Marker)}})
	if err == nil || output != nil {
		t.Fatal("binary replacement grew beyond its sensitive source extent")
	}
	text := []byte("password=x")
	output, _, err = applyEdits(text, []edit{{len(text) - 1, len(text), []byte(Marker)}})
	if err != nil || string(output) != "password=REDACTED" {
		t.Fatal("ordinary text redaction no longer uses the exact marker")
	}
}

func TestCompiledBinaryPadsAfterEncodedReplacement(t *testing.T) {
	input := elfTestBinary(bytes.Repeat([]byte("s"), 32), true, binary.LittleEndian)
	encodedMarker := []byte{'R', 0, 'E', 0, 'D', 0, 'A', 0, 'C', 0, 'T', 0, 'E', 0, 'D', 0}
	start := len(input) - 32
	output, _, err := applyEdits(input, []edit{{start, len(input), encodedMarker}})
	if err != nil || len(output) != len(input) || !bytes.Equal(output[:start], input[:start]) || !bytes.Equal(output[start:start+len(encodedMarker)], encodedMarker) || !bytes.Equal(output[start+len(encodedMarker):], bytes.Repeat([]byte{' '}, 32-len(encodedMarker))) {
		t.Fatal("compiled padding changed the encoded marker or escaped its source extent")
	}
}

func TestCompiledBinaryPaddingPreservesHTMLDecoderContext(t *testing.T) {
	const secret = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
	const public = "abcdefghijklmnopqrstuvwxyz012345"
	payload := []byte("<p>box " + secret + strings.Repeat(".", 13) + public + " keep</p>")
	input := elfTestBinary(payload, true, binary.LittleEndian)
	start := bytes.Index(input, []byte(secret))
	d := &box.Scanner{}
	html := &decoders.HTML{}
	// NUL padding preserves raw offsets but HTML drops those bytes, promoting
	// an unchanged public identifier into Box's forty-character context.
	nulPadded := bytes.Clone(input)
	clear(nulPadded[start : start+len(secret)])
	copy(nulPadded[start:start+len(secret)], Marker)
	decoded := html.FromChunkForRedaction(&sources.Chunk{Data: nulPadded})
	if decoded == nil {
		t.Fatal("synthetic compiled HTML payload was not decoded")
	}
	promoted, err := d.FromData(context.Background(), false, decoded.Data)
	if err != nil || len(promoted) != 1 || promoted[0].SecretParts["key"] != public {
		t.Fatal("fixture did not reproduce HTML dropping NUL padding")
	}
	s, _ := New([]detectors.Detector{d})
	output, report, err := s.Redact(context.Background(), input)
	if err != nil || report.Replacements != 1 || len(output) != len(input) {
		t.Fatal("compiled HTML source failed bounded fixed-width redaction")
	}
	want := bytes.Clone(input)
	copy(want[start:start+len(secret)], bytes.Repeat([]byte{' '}, len(secret)))
	copy(want[start:start+len(secret)], Marker)
	if !bytes.Equal(output, want) || !bytes.Contains(output, []byte(public)) {
		t.Fatal("compiled HTML redaction changed public bytes or source offsets")
	}
	decodedOutput := html.FromChunkForRedaction(&sources.Chunk{Data: bytes.Clone(output)})
	if decodedOutput == nil {
		t.Fatal("redacted compiled HTML payload was not decoded")
	}
	for _, data := range [][]byte{output, decodedOutput.Data} {
		remaining, err := d.FromData(context.Background(), false, data)
		if err != nil || len(remaining) != 0 {
			t.Fatal("compiled redaction introduced a raw or HTML-decoded candidate")
		}
	}
	again, second, err := s.Redact(context.Background(), output)
	if err != nil || second.Replacements != 0 || !bytes.Equal(output, again) {
		t.Fatal("compiled HTML redaction was not clean and byte-idempotent")
	}
}
