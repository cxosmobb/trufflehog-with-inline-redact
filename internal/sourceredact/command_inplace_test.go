package sourceredact

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

// This subprocess exercises main itself, including flags and exit status. A
// prebuilt production executable can be supplied for release verification.
func TestRedactCommandProcess(t *testing.T) {
	if os.Getenv("TRUFFLEHOG_REDACT_COMMAND_TEST") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{"trufflehog-redact"}, os.Args[i+1:]...)
			if err := Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
				fmt.Fprintln(os.Stderr, "source redaction failed:", err)
				os.Exit(1)
			}
			os.Exit(0)
		}
	}
	os.Exit(2)
}

func runRedactCommand(t *testing.T, args ...string) {
	t.Helper()
	binary := os.Getenv("REDACTION_TEST_BINARY")
	commandArgs := args
	if native := os.Getenv("REDACTION_TEST_MAIN_BINARY"); native != "" {
		binary = native
		commandArgs = mainCommandArgs(args)
	}
	if binary == "" {
		var err error
		binary, err = os.Executable()
		if err != nil {
			t.Fatal("cannot locate command test executable")
		}
		commandArgs = append([]string{"-test.run=^TestRedactCommandProcess$", "--"}, args...)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, binary, commandArgs...)
	command.Env = append(os.Environ(), "TRUFFLEHOG_REDACT_COMMAND_TEST=1")
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		// Never print process diagnostics: a future regression could include
		// source bytes or credentials. Failure is localized by the test name.
		t.Fatalf("redaction command failed: %v (stdout=%d bytes; stderr=%d bytes)", err, stdout.Len(), stderr.Len())
	}
	if os.Getenv("REDACTION_TEST_MAIN_BINARY") != "" {
		// Native --in-place retains ordinary JSON findings from the original
		// source. Their secret fields are intentional; never print this buffer.
		if stderr.Len() != 0 {
			t.Fatalf("native in-place command emitted diagnostics (%d bytes)", stderr.Len())
		}
		assertNativeJSONOutput(t, stdout.Bytes())
		return
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatal("successful standalone in-place command emitted source or diagnostics")
	}
}

// The full TruffleHog executable keeps its source subcommand and flag namespace.
func mainCommandArgs(args []string) []string {
	result := []string{"--no-update", "--no-verification", "--log-level=-1", "--json", "filesystem", "--in-place"}
	for _, arg := range args {
		if arg == "--in-place" {
			continue
		}
		for _, flag := range []string{"timeout", "max-bytes", "max-total-bytes", "max-files"} {
			old := "--" + flag
			if arg == old || strings.HasPrefix(arg, old+"=") {
				arg = "--redaction-" + flag + strings.TrimPrefix(arg, old)
				break
			}
		}
		result = append(result, arg)
	}
	return result
}

type exactInPlaceFixture struct {
	name        string
	input, want []byte
}

func exactInPlaceFixtures() []exactInPlaceFixture {
	const secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	plain := "// keep café and quotes\r\nconst token = \"" + secret + "\"; // keep\r\nagain = \"" + secret + "\";\r\n"
	redacted := strings.ReplaceAll(plain, secret, "REDACTED")
	fixtures := []exactInPlaceFixture{
		{"plain/repeated.go", []byte(plain), []byte(redacted)},
		{"plain/ordinary.go", []byte("// ordinary source\r\nconst answer = 42;\r\n"), []byte("// ordinary source\r\nconst answer = 42;\r\n")},
		{"plain/empty.go", nil, nil},
	}
	for _, entry := range []struct {
		name, source string
		secrets      []string
	}{
		{"structured/box-oauth.txt", "box\n" + strings.Repeat(".", 80) + "\nclient_id = '" + strings.Repeat("a1", 16) + "'\n" + strings.Repeat(".", 80) + "\nclient_secret = '" + strings.Repeat("b2", 16) + "'\n", []string{strings.Repeat("b2", 16)}},
		{"structured/jdbc-userinfo.txt", "jdbc:postgresql://public:firstSensitiveSecret@host.invalid/db?user=public&password=secondSensitiveSecret&sslmode=require", []string{"firstSensitiveSecret", "secondSensitiveSecret"}},
		{"structured/jdbc-dsn-userinfo-query.txt", "jdbc:mysql://public:firstSensitiveSecret@tcp(host.invalid:3307)/db?password=secondSensitiveSecret", []string{"firstSensitiveSecret", "secondSensitiveSecret"}},
		{"structured/jdbc-repeated.txt", "jdbc:sqlserver://host.invalid;user=public;password=firstSensitiveSecret;password=secondSensitiveSecret;encrypt=true", []string{"firstSensitiveSecret", "secondSensitiveSecret"}},
		{"structured/sas.txt", "https://publicstore.blob.core.windows.net/container/blob?sp=r&sv=2026-01-01&sr=b&se=2026-12-31T01:02:03Z&sig=firstSensitiveSignature&sig=secondSensitiveSignature", []string{"firstSensitiveSignature", "secondSensitiveSignature"}},
		{"structured/gcp.json", `{"client_email":"public-id","auth_provider_x509_cert_url":"https://public.invalid/cert","private_key":"firstSensitiveSecret","private_key":"secondSensitiveSecret"}`, []string{"firstSensitiveSecret", "secondSensitiveSecret"}},
	} {
		want := entry.source
		for _, value := range entry.secrets {
			want = strings.ReplaceAll(want, value, "REDACTED")
		}
		fixtures = append(fixtures, exactInPlaceFixture{entry.name, []byte(entry.source), []byte(want)})
	}
	for _, format := range []struct{ name, encoded string }{
		{"unicode", encodeCommandFixture(secret, "\\u%04x")},
		{"percent", encodeCommandFixture(secret, "%%%02x")},
		{"html", encodeCommandFixture(secret, "&#x%x;")},
	} {
		fixtures = append(fixtures, exactInPlaceFixture{"encoded/" + format.name + ".txt", []byte("token=\"" + format.encoded + "\"; keep=42\n"), []byte("token=\"REDACTED\"; keep=42\n")})
	}
	blob := "user=public;token=" + secret + ";keep=42"
	wantBlob := strings.ReplaceAll(blob, secret, "REDACTED")
	fixtures = append(fixtures, exactInPlaceFixture{"encoded/base64.txt", []byte("payload=\"" + base64.StdEncoding.EncodeToString([]byte(blob)) + "\"; keep=42\n"), []byte("payload=\"" + base64.StdEncoding.EncodeToString([]byte(wantBlob)) + "\"; keep=42\n")})
	for _, bigEndian := range []bool{false, true} {
		name := "encoded/utf16le.txt"
		if bigEndian {
			name = "encoded/utf16be.txt"
		}
		fixtures = append(fixtures, exactInPlaceFixture{name, wideCommandFixture(plain, bigEndian), wideCommandFixture(redacted, bigEndian)})
	}
	return fixtures
}

func encodeCommandFixture(value, format string) string {
	var result strings.Builder
	for _, char := range value {
		fmt.Fprintf(&result, format, char)
	}
	return result.String()
}

func wideCommandFixture(value string, bigEndian bool) []byte {
	units := utf16.Encode([]rune(value))
	data := make([]byte, 2+2*len(units))
	var order binary.ByteOrder = binary.LittleEndian
	data[0], data[1] = 0xff, 0xfe
	if bigEndian {
		order = binary.BigEndian
		data[0], data[1] = 0xfe, 0xff
	}
	for i, unit := range units {
		order.PutUint16(data[2+2*i:], unit)
	}
	return data
}

func TestCommandInPlaceExactMultiFileFixtures(t *testing.T) {
	requireInPlaceSecurity(t)
	dir := t.TempDir()
	fixtures := exactInPlaceFixtures()
	unchangedInfo := make(map[string]os.FileInfo)
	for _, fixture := range fixtures {
		path := writeSource(t, dir, filepath.FromSlash(fixture.name), string(fixture.input), 0640)
		if bytes.Equal(fixture.input, fixture.want) {
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			unchangedInfo[path] = info
		}
	}
	gitContent := "Git history is outside the redaction boundary: ghp_abcdefghijklmnopqrstuvwxyz0123456789\n"
	git := writeSource(t, dir, filepath.Join(".git", "config"), gitContent, 0600)
	for pass := 1; pass <= 2; pass++ {
		runRedactCommand(t, "--in-place", "--timeout=9m", dir)
		for _, fixture := range fixtures {
			path := filepath.Join(dir, filepath.FromSlash(fixture.name))
			output, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(output, fixture.want) {
				t.Fatalf("%s: source differs from exact expected bytes after pass %d", fixture.name, pass)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if original := unchangedInfo[path]; original != nil && !os.SameFile(original, info) {
				t.Fatalf("%s: unchanged source was replaced on pass %d", fixture.name, pass)
			}
			unchangedInfo[path] = info
		}
		assertSource(t, git, gitContent)
		assertNoStagedFiles(t, dir)
	}
	t.Logf("exact in-place byte preservation: %d files, 2 passes, including structured and encoded credentials", len(fixtures))
}

// Shortening a secret can bring a public identifier into a different detector's
// keyword window. Refusing this ambiguous output preserves the original batch;
// erasing the newly matched public ID or disabling the audit would violate the
// source-preservation/security contract.
func TestRunInPlaceAmbiguousBoxLeavesBatchUnchanged(t *testing.T) {
	requireInPlaceSecurity(t)
	dir := t.TempDir()
	firstContent := "const token = 'ghp_abcdefghijklmnopqrstuvwxyz0123456789';\r\n"
	first := writeSource(t, dir, "a-source.go", firstContent, 0640)
	ambiguous := "box secret = '" + strings.Repeat("s", 32) + "'; client_id = '" + strings.Repeat("p", 32) + "';\n"
	second := writeSource(t, dir, "b-box.txt", ambiguous, 0640)
	var stdout, stderr bytes.Buffer
	err := run([]string{"--in-place", dir}, strings.NewReader(""), &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "detector Box found residual") {
		t.Fatal("ambiguous new token finding did not withhold the source batch")
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatal("failed in-place batch emitted source bytes or diagnostics")
	}
	assertSource(t, first, firstContent)
	assertSource(t, second, ambiguous)
	assertNoStagedFiles(t, dir)
}

func TestRunInPlaceMalformedConnectionLeavesBatchUnchanged(t *testing.T) {
	requireInPlaceSecurity(t)
	dir := t.TempDir()
	firstContent := "const token = 'ghp_abcdefghijklmnopqrstuvwxyz0123456789';\n"
	first := writeSource(t, dir, "a-source.go", firstContent, 0640)
	malformed := "jdbc:postgresql://public:first%GGSecret@host.invalid/db?password=secondSensitiveSecret"
	second := writeSource(t, dir, "b-connection.txt", malformed, 0640)
	var stdout, stderr bytes.Buffer
	if err := run([]string{"--in-place", dir}, strings.NewReader(""), &stdout, &stderr); err == nil {
		t.Fatal("unparsed userinfo credential did not withhold the source batch")
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatal("failed in-place batch emitted source bytes or diagnostics")
	}
	assertSource(t, first, firstContent)
	assertSource(t, second, malformed)
	assertNoStagedFiles(t, dir)
}
