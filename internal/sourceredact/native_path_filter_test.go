package sourceredact

import (
	"context"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func TestRedactInPlaceNativePathFiltersPreserveInputSpelling(t *testing.T) {
	for _, absolute := range []bool{false, true} {
		name := "relative"
		if absolute {
			name = "absolute"
		}
		t.Run(name, func(t *testing.T) {
			requireInPlaceSecurity(t)
			dir := t.TempDir()
			t.Chdir(dir)
			selected := writeSource(t, dir, "src/included/first.go", "SYNTHETIC_SECRET selected", 0600)
			fileExcluded := writeSource(t, dir, "src/included/excluded.go", "SYNTHETIC_SECRET file excluded", 0600)
			dirExcluded := writeSource(t, dir, "src/excluded/nested/first.go", "SYNTHETIC_SECRET directory excluded", 0600)
			notIncluded := writeSource(t, dir, "src/included/other.txt", "SYNTHETIC_SECRET not included", 0600)
			input := "src"
			if absolute {
				input = filepath.Join(dir, input)
			}
			include := regexp.MustCompile("^" + regexp.QuoteMeta(input) + `[\\/].*\.go$`)
			excludedDirectory := filepath.Join(input, "excluded")
			options := Defaults()
			options.NativePathFilters = true
			options.SkipDirectory = func(path string) bool {
				if filepath.IsAbs(path) != absolute {
					t.Fatal("directory filter changed the input path spelling")
				}
				return path == excludedDirectory
			}
			options.IncludePath = func(path string) bool {
				if filepath.IsAbs(path) != absolute {
					t.Fatal("file filter changed the input path spelling")
				}
				if strings.HasPrefix(path, excludedDirectory+string(filepath.Separator)) {
					t.Fatal("enumeration descended into a natively excluded directory")
				}
				return include.MatchString(path) && filepath.Base(path) != "excluded.go"
			}
			if err := RedactInPlace(context.Background(), sourceScannerFunc(replaceSyntheticSecret), []string{input}, options); err != nil {
				t.Fatal(err)
			}
			assertSource(t, selected, "REDACTED selected")
			assertSource(t, fileExcluded, "SYNTHETIC_SECRET file excluded")
			assertSource(t, dirExcluded, "SYNTHETIC_SECRET directory excluded")
			assertSource(t, notIncluded, "SYNTHETIC_SECRET not included")
			assertNoStagedFiles(t, dir)
		})
	}
}

func TestSourceFilesNativePathFiltersUnionOverlappingInputs(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	relativeSelected := writeSource(t, dir, "src/relative.go", "relative", 0600)
	absoluteSelected := writeSource(t, dir, "src/absolute.go", "absolute", 0600)
	writeSource(t, dir, "src/excluded.go", "excluded", 0600)
	absoluteRoot := filepath.Join(dir, "src")
	for _, inputs := range [][]string{{"src", absoluteRoot}, {absoluteRoot, "src"}} {
		include := func(path string) bool {
			return path == filepath.Join("src", "relative.go") || path == absoluteSelected
		}
		got, err := sourceFilesSelected(context.Background(), inputs, 100, include, nil, true)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{relativeSelected, absoluteSelected}
		sort.Strings(want)
		if !reflect.DeepEqual(got, want) {
			t.Fatal("overlapping input spellings did not retain the union of native selections")
		}
	}
}

func TestRedactInPlaceNativePathFiltersSelectExplicitFiles(t *testing.T) {
	requireInPlaceSecurity(t)
	dir := t.TempDir()
	t.Chdir(dir)
	path := writeSource(t, dir, "explicit.go", "SYNTHETIC_SECRET explicit", 0600)
	options := Defaults()
	options.NativePathFilters = true
	options.IncludePath = func(string) bool {
		t.Fatal("native filesystem filters do not apply to explicit regular-file arguments")
		return false
	}
	options.SkipDirectory = func(string) bool {
		t.Fatal("explicit regular-file argument was treated as a directory")
		return true
	}
	if err := RedactInPlace(context.Background(), sourceScannerFunc(replaceSyntheticSecret), []string{"explicit.go"}, options); err != nil {
		t.Fatal(err)
	}
	assertSource(t, path, "REDACTED explicit")
	assertNoStagedFiles(t, dir)
}
