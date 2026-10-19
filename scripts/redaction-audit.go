//go:build ignore

// redaction-audit inventories the detector result schema without printing credentials.
// Run from the repository root: go run ./scripts/redaction-audit.go
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type fileSchema struct {
	Path       string   `json:"path"`
	SHA256     string   `json:"sha256"`
	PartKeys   []string `json:"part_keys"`
	FromData   bool     `json:"from_data"`
	Delegating bool     `json:"delegating"`
}

type report struct {
	ProductionFiles int            `json:"production_files"`
	ResultFiles     int            `json:"result_files"`
	Keys            []string       `json:"keys"`
	KeyFiles        map[string]int `json:"key_file_counts"`
	Files           []fileSchema   `json:"files"`
	PipelineFiles   []fileSchema   `json:"pipeline_files"`
	Unclassified    []string       `json:"dynamic_schema_expressions,omitempty"`
}

type mapSchema struct {
	keys       map[string]bool
	dynamic    []token.Pos
	credential bool
}

// auditFile treats computed credential keys and opaque map assignments as
// unresolved, rather than silently producing an apparently complete inventory.
// It does not evaluate expressions or execute the detector being inspected.
func auditFile(path string, data []byte) (fileSchema, []string, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, data, 0)
	if err != nil {
		return fileSchema{}, nil, err
	}
	schema := fileSchema{Path: filepath.ToSlash(path)}
	hash := sha256.Sum256([]byte(strings.ReplaceAll(string(data), "\r\n", "\n")))
	schema.SHA256 = hex.EncodeToString(hash[:])
	keys := make(map[string]bool)
	unclassified := make(map[string]bool)
	addKey := func(mapping *mapSchema, expr ast.Expr) {
		if literal, ok := expr.(*ast.BasicLit); ok && literal.Kind == token.STRING {
			if key, err := strconv.Unquote(literal.Value); err == nil {
				mapping.keys[key] = true
				return
			}
		}
		mapping.dynamic = append(mapping.dynamic, expr.Pos())
	}
	readMap := func(expr ast.Expr) *mapSchema {
		mapping := &mapSchema{keys: make(map[string]bool)}
		switch n := expr.(type) {
		case *ast.CompositeLit:
			if _, ok := n.Type.(*ast.MapType); !ok {
				return nil
			}
			for _, item := range n.Elts {
				if kv, ok := item.(*ast.KeyValueExpr); ok {
					addKey(mapping, kv.Key)
				}
			}
		case *ast.CallExpr:
			name, ok := n.Fun.(*ast.Ident)
			if !ok || name.Name != "make" || len(n.Args) == 0 {
				return nil
			}
			if _, ok := n.Args[0].(*ast.MapType); !ok {
				return nil
			}
		case *ast.SelectorExpr:
			if n.Sel.Name != "SecretParts" {
				return nil
			}
			mapping.credential = true
		default:
			return nil
		}
		return mapping
	}
	recordMap := func(mapping *mapSchema) {
		for key := range mapping.keys {
			keys[key] = true
		}
		for _, position := range mapping.dynamic {
			unclassified[fset.Position(position).String()] = true
		}
	}
	// Local names are scoped per function, so another function's map cannot
	// conceal an opaque SecretParts assignment with the same variable name.
	scanScope := func(node ast.Node, globals map[string]*mapSchema) map[string]*mapSchema {
		maps := make(map[string]*mapSchema)
		for name, mapping := range globals {
			maps[name] = mapping
		}
		inspect := func(visit func(ast.Node)) {
			ast.Inspect(node, func(n ast.Node) bool {
				if n == nil {
					return false
				}
				if _, ok := n.(*ast.FuncDecl); ok && n != node {
					return false
				}
				visit(n)
				return true
			})
		}
		remember := func(name string, value ast.Expr) {
			if mapping := readMap(value); mapping != nil {
				if previous := maps[name]; previous != nil {
					for key := range previous.keys {
						mapping.keys[key] = true
					}
					mapping.dynamic = append(mapping.dynamic, previous.dynamic...)
				}
				maps[name] = mapping
			} else if alias, ok := value.(*ast.Ident); ok && maps[alias.Name] != nil {
				maps[name] = maps[alias.Name]
			} else {
				mapping := &mapSchema{keys: make(map[string]bool), dynamic: []token.Pos{value.Pos()}}
				if previous := maps[name]; previous != nil {
					mapping.keys = previous.keys
					mapping.dynamic = append(mapping.dynamic, previous.dynamic...)
				}
				maps[name] = mapping
			}
		}
		inspect(func(n ast.Node) {
			switch n := n.(type) {
			case *ast.ValueSpec:
				for i, value := range n.Values {
					if i < len(n.Names) {
						remember(n.Names[i].Name, value)
					}
				}
			case *ast.AssignStmt:
				for i, value := range n.Rhs {
					if i < len(n.Lhs) {
						if name, ok := n.Lhs[i].(*ast.Ident); ok {
							remember(name.Name, value)
						}
					}
				}
			}
		})
		inspect(func(n ast.Node) {
			assign, ok := n.(*ast.AssignStmt)
			if !ok {
				return
			}
			for _, lhs := range assign.Lhs {
				if index, ok := lhs.(*ast.IndexExpr); ok {
					if name, ok := index.X.(*ast.Ident); ok && maps[name.Name] != nil {
						addKey(maps[name.Name], index.Index)
					}
				}
			}
		})
		recordValue := func(value ast.Expr) {
			if name, ok := value.(*ast.Ident); ok {
				if name.Name == "nil" {
					return // ClearSecrets deliberately discards its map.
				}
				if mapping := maps[name.Name]; mapping != nil {
					recordMap(mapping)
					return
				}
			}
			if mapping := readMap(value); mapping != nil {
				recordMap(mapping)
			} else {
				unclassified[fset.Position(value.Pos()).String()] = true
			}
		}
		inspect(func(n ast.Node) {
			switch n := n.(type) {
			case *ast.KeyValueExpr:
				if name, ok := n.Key.(*ast.Ident); ok && name.Name == "SecretParts" {
					recordValue(n.Value)
				}
			case *ast.AssignStmt:
				for i, lhs := range n.Lhs {
					if field, ok := lhs.(*ast.SelectorExpr); ok && field.Sel.Name == "SecretParts" && i < len(n.Rhs) {
						recordValue(n.Rhs[i])
					}
					if index, ok := lhs.(*ast.IndexExpr); ok {
						if field, ok := index.X.(*ast.SelectorExpr); ok && field.Sel.Name == "SecretParts" {
							mapping := &mapSchema{keys: make(map[string]bool)}
							addKey(mapping, index.Index)
							recordMap(mapping)
						}
					}
				}
			}
		})
		for _, mapping := range maps {
			if mapping.credential {
				recordMap(mapping)
			}
		}
		return maps
	}
	globals := scanScope(file, nil)
	for _, declaration := range file.Decls {
		if fn, ok := declaration.(*ast.FuncDecl); ok {
			if fn.Name.Name == "FromData" {
				schema.FromData = true
			}
			scanScope(fn, globals)
		}
	}
	for key := range keys {
		schema.PartKeys = append(schema.PartKeys, key)
	}
	sort.Strings(schema.PartKeys)
	schema.Delegating = schema.FromData && len(keys) == 0
	var dynamic []string
	for position := range unclassified {
		dynamic = append(dynamic, position)
	}
	sort.Strings(dynamic)
	return schema, dynamic, nil
}

func main() {
	root := "pkg/detectors"
	if len(os.Args) == 2 {
		root = os.Args[1]
	}
	r := report{KeyFiles: make(map[string]int)}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		schema, dynamic, err := auditFile(path, data)
		if err != nil {
			return err
		}
		r.ProductionFiles++
		if len(schema.PartKeys) != 0 {
			r.ResultFiles++
		}
		for _, key := range schema.PartKeys {
			r.KeyFiles[key]++
		}
		r.Unclassified = append(r.Unclassified, dynamic...)
		r.Files = append(r.Files, schema)
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "detector schema audit failed:", err)
		os.Exit(1)
	}
	for _, pipelineRoot := range []string{"pkg/decoders", "pkg/engine/defaults"} {
		err := filepath.WalkDir(pipelineRoot, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			hash := sha256.Sum256([]byte(strings.ReplaceAll(string(data), "\r\n", "\n")))
			r.PipelineFiles = append(r.PipelineFiles, fileSchema{Path: filepath.ToSlash(path), SHA256: hex.EncodeToString(hash[:])})
			return nil
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "pipeline schema audit failed:", err)
			os.Exit(1)
		}
	}
	for key := range r.KeyFiles {
		r.Keys = append(r.Keys, key)
	}
	sort.Strings(r.Keys)
	sort.Strings(r.Unclassified)
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(r); err != nil {
		fmt.Fprintln(os.Stderr, "cannot encode detector schema audit:", err)
		os.Exit(1)
	}
}
