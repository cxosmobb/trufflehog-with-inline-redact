package sourceredact

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestCommandRedactsZIPInPlace(t *testing.T) {
	requireInPlaceSecurity(t)
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for _, member := range []struct{ name, data string }{{"config.txt", "token='ghp_abcdefghijklmnopqrstuvwxyz0123456789'; keep=42\n"}, {"unrelated.txt", "keep original bytes\n"}} {
		out, err := writer.Create(member.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(out, member.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if unsupportedContainer(buffer.Bytes()) {
		t.Fatal("supported ZIP could not reach the redaction scanner")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "challenge.jar")
	if err := os.WriteFile(path, buffer.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	runRedactCommand(t, "--in-place", dir)
	redacted, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := zip.NewReader(bytes.NewReader(redacted), int64(len(redacted)))
	if err != nil || len(reader.File) != 2 {
		t.Fatal("in-place ZIP was corrupted")
	}
	for i, want := range []string{"token='REDACTED'; keep=42\n", "keep original bytes\n"} {
		member, err := reader.File[i].Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(member)
		_ = member.Close()
		if err != nil || string(data) != want {
			t.Fatal("in-place ZIP did not preserve exact non-sensitive logical bytes")
		}
	}
	runRedactCommand(t, "--in-place", dir)
	again, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(again, redacted) {
		t.Fatal("second ZIP redaction changed an already clean archive")
	}
	assertNoStagedFiles(t, dir)
}
