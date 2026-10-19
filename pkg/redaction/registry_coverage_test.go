package redaction_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
)

// Compare against the ungated registry literal, rather than DefaultDetectors:
// runtime feature flags can hide an otherwise supported scanner. This catches
// accidental registry omissions without activating intentionally disabled types.
func TestRedactionRegistryContainsEveryActiveAndGatedDetector(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), filepath.Join("..", "engine", "defaults", "defaults.go"), nil, 0)
	if err != nil {
		t.Fatal("cannot parse upstream detector registry")
	}
	imports := make(map[string]string)
	for _, item := range file.Imports {
		pkg, err := strconv.Unquote(item.Path.Value)
		if err != nil {
			t.Fatal("invalid registry import")
		}
		alias := path.Base(pkg)
		if item.Name != nil {
			alias = item.Name.Name
		}
		imports[alias] = pkg
	}
	var entries []ast.Expr
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "buildDetectorList" {
			continue
		}
		for _, stmt := range fn.Body.List {
			assignment, ok := stmt.(*ast.AssignStmt)
			if !ok || assignment.Tok != token.DEFINE || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
				continue
			}
			name, ok := assignment.Lhs[0].(*ast.Ident)
			if !ok || name.Name != "dets" {
				continue
			}
			literal, ok := assignment.Rhs[0].(*ast.CompositeLit)
			if !ok {
				t.Fatal("upstream detector registry changed shape; review coverage")
			}
			entries = literal.Elts
		}
	}
	if len(entries) == 0 {
		t.Fatal("upstream active detector registry is empty or unrecognized")
	}
	expected := make(map[string]bool)
	for _, entry := range entries {
		var selector *ast.SelectorExpr
		switch item := entry.(type) {
		case *ast.UnaryExpr:
			if literal, ok := item.X.(*ast.CompositeLit); ok {
				selector, _ = literal.Type.(*ast.SelectorExpr)
			}
		case *ast.CallExpr:
			selector, _ = item.Fun.(*ast.SelectorExpr)
		}
		if selector == nil {
			t.Fatal("unrecognized active scanner construction; review coverage")
		}
		alias, ok := selector.X.(*ast.Ident)
		if !ok || imports[alias.Name] == "" {
			t.Fatal("cannot resolve active scanner package")
		}
		expected[imports[alias.Name]] = true
	}
	// Upstream explicitly records these implementations as mistakenly omitted.
	// Keep the source-redaction-only additions explicit and separately reviewed.
	expected["github.com/trufflesecurity/trufflehog/v3/pkg/detectors/guru"] = true
	expected["github.com/trufflesecurity/trufflehog/v3/pkg/detectors/tru"] = true
	seenTypes := make(map[reflect.Type]bool)
	seenPackages := make(map[string]bool)
	for _, detector := range defaults.RedactionDetectors() {
		typ := reflect.TypeOf(detector)
		for typ.Kind() == reflect.Pointer {
			typ = typ.Elem()
		}
		if seenTypes[typ] {
			t.Errorf("duplicate source-redaction scanner: %s", typ)
		}
		seenTypes[typ] = true
		pkg := typ.PkgPath()
		if !expected[pkg] {
			t.Errorf("unreviewed source-redaction scanner package: %s", pkg)
		}
		seenPackages[pkg] = true
	}
	for pkg := range expected {
		if !seenPackages[pkg] {
			t.Errorf("active or gated upstream scanner missing from source redaction: %s", pkg)
		}
	}
}
