// Package redactiontest shares offline samples between engine and command tests.
// Production commands never import this test fixture generator.
package redactiontest

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp/syntax"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
	"github.com/trufflesecurity/trufflehog/v3/pkg/redaction"
)

// Fixture keeps source and expected edits in memory; never print these buffers.
// Expected is the validated singleton-detector engine result, not an independent
// byte-range oracle. Exact standalone fixtures cover edit policy separately.
type Fixture struct {
	Name     string
	Detector detectors.Detector
	Input    []byte
	Expected []byte
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal("cannot locate fixture repository")
	}
	for {
		info, err := os.Stat(filepath.Join(dir, "pkg", "detectors"))
		if err == nil && info.IsDir() {
			if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("cannot locate fixture repository")
		}
		dir = parent
	}
}

// Fixtures selects one positive, source-mappable offline sample per registered scanner.
// Fixture candidates come from the detector's own patterns and committed tests;
// no candidate, result, or secret-bearing error is written to the test log.
func Fixtures(t *testing.T) []Fixture {
	t.Helper()
	var fixtures []Fixture
	if testing.Short() {
		if os.Getenv("REDACTION_REQUIRE_IN_PLACE") == "1" {
			t.Fatal("required all-detector coverage cannot use short mode")
		}
		t.Skip("all-detector corpus check is omitted in short mode")
	}
	root := repositoryRoot(t)
	var detectionGaps, mappingGaps []string
	covered := 0
	selected := os.Getenv("REDACTION_TEST_DETECTORS")
	if selected != "" && os.Getenv("REDACTION_REQUIRE_IN_PLACE") == "1" {
		t.Fatal("required all-detector coverage cannot use a detector selection filter")
	}
	selection := make(map[string]bool)
	for _, name := range strings.Split(selected, ",") {
		selection[strings.TrimSpace(name)] = true
	}
	tested := 0
	fixtureContext := logContext.WithLogger(context.Background(), logr.Discard())
	for _, detector := range defaults.RedactionDetectors() {
		name := detector.Type().String()
		if versioned, ok := detector.(detectors.Versioner); ok {
			name = fmt.Sprintf("%s.v%d", name, versioned.Version())
		}
		if selected != "" && !selection[name] {
			continue
		}
		tested++
		typ := reflect.TypeOf(detector)
		for typ.Kind() == reflect.Pointer {
			typ = typ.Elem()
		}
		pkg := strings.TrimPrefix(typ.PkgPath(), "github.com/trufflesecurity/trufflehog/v3/")
		candidates, err := detectorCandidates(filepath.Join(root, filepath.FromSlash(pkg)))
		if err != nil {
			t.Fatalf("%s: cannot read synthetic fixture sources", name)
		}
		candidates = append(specialCandidates(name), candidates...)
		scanner, err := redaction.New([]detectors.Detector{detector})
		if err != nil {
			t.Fatalf("%s: cannot construct redaction scanner", name)
		}
		detected, mapped := false, false
		lastMappingReason := "no replacement"
		for _, candidate := range candidates {
			data := []byte("前置上下文\n" + strings.Join(detector.Keywords(), " ") + "\n" + candidate + "\n后置上下文")
			results, err := detector.FromData(fixtureContext, false, data)
			if err != nil || len(results) == 0 {
				continue
			}
			detected = true
			output, report, err := scanner.Redact(context.Background(), data)
			if err != nil || report.Replacements == 0 {
				if err != nil {
					lastMappingReason = err.Error() // Scanner errors contain no source material.
				}
				continue
			}
			if !strings.HasPrefix(string(output), "前置上下文\n") || !strings.HasSuffix(string(output), "\n后置上下文") {
				t.Fatalf("%s: redaction changed surrounding fixture context", name)
			}
			// Source-editing component additions must never expand the normal
			// scanner's JSON findings with previously omitted secret fields.
			if part := sourceOnlyPart(name); part != "" {
				for _, result := range results {
					if _, exposed := result.SecretParts[part]; exposed {
						t.Fatalf("%s: ordinary findings exposed a source-only component", name)
					}
				}
				sourceResults, err := detector.FromData(detectors.WithSourceRedaction(fixtureContext), false, data)
				if err != nil || len(sourceResults) == 0 {
					t.Fatalf("%s: source-only component extraction failed", name)
				}
				for _, result := range sourceResults {
					if result.SecretParts[part] == "" {
						t.Fatalf("%s: source-only component missing", name)
					}
				}
			}
			fixtures = append(fixtures, Fixture{Name: name, Detector: detector, Input: data, Expected: output})
			mapped = true
			break
		}
		if !detected {
			detectionGaps = append(detectionGaps, name)
		} else if !mapped {
			mappingGaps = append(mappingGaps, name)
			t.Logf("%s mapping reason: %s", name, lastMappingReason)
		} else {
			covered++
		}
	}
	sort.Strings(detectionGaps)
	sort.Strings(mappingGaps)
	if tested == 0 {
		t.Fatal("detector selection matched no scanners")
	}
	t.Logf("positive redaction coverage: %d/%d scanners; detection gaps: %d; source mapping gaps: %d", covered, tested, len(detectionGaps), len(mappingGaps))
	if len(detectionGaps) != 0 {
		t.Errorf("scanners lacking a positive offline fixture: %s", strings.Join(detectionGaps, ", "))
	}
	if len(mappingGaps) != 0 {
		t.Errorf("scanners detecting a fixture whose sensitive values cannot be mapped: %s", strings.Join(mappingGaps, ", "))
	}
	if t.Failed() {
		t.FailNow()
	}
	return fixtures
}

func sourceOnlyPart(name string) string {
	name, _, _ = strings.Cut(name, ".v")
	switch name {
	case "ApiFonica", "Netsuite", "SatismeterWritekey", "TrelloApiKey":
		return "token"
	case "ClickHelp":
		return "key"
	case "Guru", "Mrticktock":
		return "password"
	case "Instamojo":
		return "client_secret"
	case "Bitfinex", "Demio", "GoDaddy", "KuCoin", "PusherChannelKey", "SquareApp", "TrufflehogEnterprise":
		return "secret"
	}
	return ""
}

func specialCandidates(name string) []string {
	switch name {
	case "BoxOauth":
		// The token and OAuth detectors share a 32-character format. Keep the
		// provider keyword away from public IDs even after a secret shrinks.
		// Ambiguous context that creates a new token finding is tested as an
		// expected withheld batch, rather than erasing a public client ID.
		padding := strings.Repeat(".", 80) + "\n"
		return []string{padding + "client_id = '" + strings.Repeat("a1", 16) + "'\n" + padding + "client_secret = '" + strings.Repeat("b2", 16) + "'\n"}
	case "Auth0ManagementApiToken":
		return []string{"auth0 https://redact.us.auth0.com\ney" + strings.Repeat("A", 2100)}
	case "JiraToken.v1":
		return []string{"jira email=redactuser@redact.atlassian.net\njira token=" + strings.Repeat("aB9", 8)}
	case "Snowflake":
		return []string{"snowflake\naccount=ABCDEFG-SYNTHETIC01\nusername=redact_user\npassword=MiXeD9SafeSecret"}
	case "ClickHelp":
		return []string{"portal.clickhelp.co\nredact@redaction.example\nclickhelp key=" + strings.Repeat("cD8", 8)}
	case "OneLogin":
		return []string{"onelogin\nclient_id = " + strings.Repeat("a1b2", 16) + "\nclient_secret = " + strings.Repeat("c3d4", 16)}
	case "PusherChannelKey":
		// Public keys and secrets share a format. Keep unrelated labels beyond
		// upstream's 40-byte provider context even after the secret is shortened.
		padding := strings.Repeat(".", 80) + "\n"
		return []string{padding + "key = " + strings.Repeat("a1", 10) + "\n" + padding + "pusher app = 1234567\n" + padding + "pusher secret = " + strings.Repeat("b2", 10)}
	}
	return nil
}

type fixtureExpr struct {
	name string
	expr ast.Expr
}

func detectorCandidates(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var expressions []fixtureExpr
	var patterns []ast.Expr
	var literals []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.Contains(entry.Name(), "integration") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, entry.Name()), nil, 0)
		if err != nil {
			return nil, err
		}
		isTest := strings.HasSuffix(entry.Name(), "_test.go")
		ast.Inspect(file, func(node ast.Node) bool {
			switch n := node.(type) {
			case *ast.BasicLit:
				if isTest && n.Kind == token.STRING {
					if value, err := strconv.Unquote(n.Value); err == nil && len(value) >= 10 && len(value) <= 65536 {
						literals = append(literals, value)
					}
				}
			case *ast.ValueSpec:
				for i, value := range n.Values {
					if i < len(n.Names) {
						expressions = append(expressions, fixtureExpr{n.Names[i].Name, value})
					}
				}
			case *ast.AssignStmt:
				for i, value := range n.Rhs {
					if i < len(n.Lhs) {
						if name, ok := n.Lhs[i].(*ast.Ident); ok {
							expressions = append(expressions, fixtureExpr{name.Name, value})
						}
					}
				}
			case *ast.CallExpr:
				if fn, ok := n.Fun.(*ast.SelectorExpr); ok && (fn.Sel.Name == "MustCompile" || fn.Sel.Name == "Compile") && len(n.Args) > 0 {
					patterns = append(patterns, n.Args[0])
				}
			}
			return true
		})
	}
	env := make(map[string]string)
	for range 8 {
		for _, expr := range expressions {
			if value, ok := fixtureString(expr.expr, env); ok {
				env[expr.name] = value
			}
		}
	}
	var generated []string
	for patternIndex, expr := range patterns {
		pattern, ok := fixtureString(expr, env)
		if !ok {
			continue
		}
		re, err := syntax.Parse(pattern, syntax.Perl)
		if err != nil {
			continue
		}
		for seed := uint64(1); seed <= 8; seed++ {
			state := (seed + uint64(patternIndex)*1009) * 0x9e3779b97f4a7c15
			generated = append(generated, syntheticMatch(re, &state, int(seed)))
		}
	}
	// Multipart detectors require all credential components in the same input.
	if len(generated) != 0 {
		generated = append(generated, strings.Join(generated, "\n"))
		// Some extractors require field labels in addition to provider words.
		// Retain the original generated form too; wrappers are only candidates.
		var labeled strings.Builder
		for _, value := range generated {
			if len(value) > 4096 {
				continue
			}
			for _, label := range []string{"key", "secret", "token", "client_id", "client_secret", "password", "account", "project_id", "tenant_id"} {
				fmt.Fprintf(&labeled, "%s = %q\n", label, value)
			}
		}
		generated = append(generated, labeled.String())
	}
	var named []string
	for _, expr := range expressions {
		value, ok := env[expr.name]
		if !ok || len(value) < 10 || len(value) > 65536 {
			continue
		}
		lower := strings.ToLower(expr.name)
		if strings.Contains(lower, "valid") || strings.Contains(lower, "secret") || strings.Contains(lower, "key") || strings.Contains(lower, "token") || lower == "input" || lower == "data" {
			named = append(named, value)
		}
	}
	if len(named) > 0 {
		generated = append(generated, strings.Join(named, "\n"))
	}
	all := append(generated, named...)
	all = append(all, literals...)
	if joined := strings.Join(literals, "\n"); len(joined) <= 262144 {
		all = append(all, joined)
	}
	seen := make(map[string]bool)
	unique := make([]string, 0, len(all))
	for _, value := range all {
		if value != "" && len(value) <= 262144 && !seen[value] {
			seen[value] = true
			unique = append(unique, value)
		}
	}
	return unique, nil
}

func fixtureString(expr ast.Expr, env map[string]string) (string, bool) {
	switch n := expr.(type) {
	case *ast.BasicLit:
		if n.Kind == token.STRING {
			value, err := strconv.Unquote(n.Value)
			return value, err == nil
		}
	case *ast.Ident:
		value, ok := env[n.Name]
		return value, ok
	case *ast.BinaryExpr:
		if n.Op == token.ADD {
			left, okL := fixtureString(n.X, env)
			right, okR := fixtureString(n.Y, env)
			return left + right, okL && okR
		}
	case *ast.CallExpr:
		if id, ok := n.Fun.(*ast.Ident); ok && id.Name == "string" && len(n.Args) == 1 {
			return fixtureString(n.Args[0], env)
		}
		fn, ok := n.Fun.(*ast.SelectorExpr)
		if !ok {
			return "", false
		}
		if fn.Sel.Name == "PrefixRegex" && len(n.Args) == 1 {
			if list, ok := n.Args[0].(*ast.CompositeLit); ok {
				var keywords []string
				for _, item := range list.Elts {
					if word, ok := fixtureString(item, env); ok {
						keywords = append(keywords, word)
					}
				}
				return detectors.PrefixRegex(keywords), len(keywords) > 0
			}
		}
		if fn.Sel.Name == "Sprintf" && len(n.Args) > 0 {
			format, ok := fixtureString(n.Args[0], env)
			if !ok {
				return "", false
			}
			var args []any
			for _, arg := range n.Args[1:] {
				value, ok := fixtureString(arg, env)
				if !ok {
					return "", false
				}
				args = append(args, value)
			}
			return fmt.Sprintf(format, args...), true
		}
	}
	return "", false
}

func syntheticMatch(re *syntax.Regexp, state *uint64, variant int) string {
	next := func(max uint64) uint64 {
		*state ^= *state << 13
		*state ^= *state >> 7
		*state ^= *state << 17
		return *state % max
	}
	switch re.Op {
	case syntax.OpLiteral:
		return string(re.Rune)
	case syntax.OpCharClass:
		var choices []rune
		for i := 0; i < len(re.Rune); i += 2 {
			start, end := re.Rune[i], re.Rune[i+1]
			for ch := max(start, 33); ch <= min(end, 126); ch++ {
				choices = append(choices, ch)
			}
		}
		if len(choices) == 0 {
			return " "
		}
		return string(choices[next(uint64(len(choices)))])
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return " "
	case syntax.OpCapture:
		return syntheticMatch(re.Sub[0], state, variant)
	case syntax.OpConcat:
		var output strings.Builder
		for _, sub := range re.Sub {
			output.WriteString(syntheticMatch(sub, state, variant))
		}
		return output.String()
	case syntax.OpAlternate:
		return syntheticMatch(re.Sub[variant%len(re.Sub)], state, variant)
	case syntax.OpQuest:
		if variant%2 == 0 {
			return syntheticMatch(re.Sub[0], state, variant)
		}
	case syntax.OpStar, syntax.OpPlus, syntax.OpRepeat:
		count := 2
		if re.Op == syntax.OpRepeat {
			count = re.Min
			if count == 0 && re.Max != 0 {
				count = min(2, re.Max)
			}
		}
		count = min(count, 4096)
		var output strings.Builder
		for range count {
			output.WriteString(syntheticMatch(re.Sub[0], state, variant))
		}
		return output.String()
	}
	return ""
}
