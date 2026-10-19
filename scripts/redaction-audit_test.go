//go:build ignore

package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestAuditCredentialMapConstruction(t *testing.T) {
	tests := []struct {
		name       string
		source     string
		keys       []string
		unresolved bool
	}{
		{"literal", `func FromData() { _ = Result{SecretParts: map[string]string{"key": "synthetic"}} }`, []string{"key"}, false},
		{"local writes", `func FromData() { parts := make(map[string]string); parts["key"] = "synthetic"; result.SecretParts = parts }`, []string{"key"}, false},
		{"direct assignment", `func FromData() { result.SecretParts = map[string]string{"token": "synthetic"} }`, []string{"token"}, false},
		{"direct mutation", `func FromData() { result.SecretParts["token"] = "synthetic" }`, []string{"token"}, false},
		{"map alias", `func FromData() { parts := map[string]string{"key": "synthetic"}; alias := parts; alias["token"] = "synthetic"; _ = Result{SecretParts: parts} }`, []string{"key", "token"}, false},
		{"field alias", `func FromData() { parts := result.SecretParts; parts["token"] = "synthetic" }`, []string{"token"}, false},
		{"computed literal", `func FromData() { parts := map[string]string{computed(): "synthetic"}; _ = Result{SecretParts: parts} }`, nil, true},
		{"computed local mutation", `func FromData() { parts := map[string]string{"key": "synthetic"}; parts[computed()] = "synthetic"; _ = Result{SecretParts: parts} }`, []string{"key"}, true},
		{"computed direct mutation", `func FromData() { result.SecretParts[computed()] = "synthetic" }`, nil, true},
		{"opaque direct assignment", `func FromData() { result.SecretParts = opaque() }`, nil, true},
		{"opaque local reassignment", `func FromData() { parts := map[string]string{"key": "synthetic"}; parts = opaque(); _ = Result{SecretParts: parts} }`, []string{"key"}, true},
		{"different function scopes", `func unrelated() { parts := map[string]string{"key": "synthetic"} }; func FromData() { parts := opaque(); _ = Result{SecretParts: parts} }`, nil, true},
		{"unrelated dynamic map", `func FromData() { extra := map[string]string{computed(): "synthetic"}; _ = Result{SecretParts: map[string]string{"key": "synthetic"}, ExtraData: extra} }`, []string{"key"}, false},
		{"clear secrets", `func ClearSecrets() { result.SecretParts = nil }`, nil, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			schema, dynamic, err := auditFile("synthetic.go", []byte("package synthetic\n"+test.source))
			if err != nil {
				t.Fatal("cannot audit synthetic source")
			}
			if !reflect.DeepEqual(schema.PartKeys, test.keys) {
				t.Errorf("keys = %v, want %v", schema.PartKeys, test.keys)
			}
			if (len(dynamic) != 0) != test.unresolved {
				t.Errorf("unresolved component status = %t, want %t", len(dynamic) != 0, test.unresolved)
			}
			for _, position := range dynamic {
				if !strings.HasPrefix(position, "synthetic.go:") || strings.Contains(position, "synthetic\"") {
					t.Fatal("unresolved diagnostics must contain only source positions")
				}
			}
		})
	}
}

func TestAuditRejectsInvalidSource(t *testing.T) {
	if _, _, err := auditFile("invalid.go", []byte("package \"synthetic\"")); err == nil {
		t.Fatal("invalid detector source was accepted")
	}
}

func TestAuditHashNormalizesLineEndings(t *testing.T) {
	lf := []byte("package synthetic\nfunc FromData() {}\n")
	crlf := []byte(strings.ReplaceAll(string(lf), "\n", "\r\n"))
	one, _, err := auditFile("synthetic.go", lf)
	if err != nil {
		t.Fatal("cannot audit LF source")
	}
	two, _, err := auditFile("synthetic.go", crlf)
	if err != nil || one.SHA256 != two.SHA256 {
		t.Fatal("detector hash depends on checkout line endings")
	}
}
