//go:build windows

package sourceredact

import "testing"

func TestWindowsLargeSourceProcessKillRecovery(t *testing.T) {
	// Only the test subprocess reads this setting; production has no crash hook.
	t.Setenv("TRUFFLEHOG_REDACT_CRASH_LARGE", "1")
	fixture := newWindowsCrashFixture(t, false)
	if len(fixture.originals[1]) <= 32<<20 || len(fixture.originals[1]) > 64<<20 {
		t.Fatal("large recovery fixture does not exercise the newly supported range")
	}
	crashWindowsFixture(t, fixture, "commit-partial")
	assertWindowsCrashTornSource(t, fixture)
	// Interrupt undo itself, then require a fresh process to restore originals
	// before scanning and finish exact redaction with all metadata intact.
	crashWindowsFixture(t, fixture, "recover-partial")
	assertWindowsCrashTornSource(t, fixture)
	retryWindowsFixture(t, fixture)
}
