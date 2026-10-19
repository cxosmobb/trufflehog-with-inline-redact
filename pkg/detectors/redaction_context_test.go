package detectors

import (
	"context"
	"testing"
	"time"
)

func TestSourceRedactionRequiresExplicitOptIn(t *testing.T) {
	plain := context.Background()
	if SourceRedactionEnabled(plain) {
		t.Fatal("ordinary scans must not acquire additional sensitive components")
	}
	derived := WithSourceRedaction(plain)
	if !SourceRedactionEnabled(derived) || SourceRedactionEnabled(plain) {
		t.Fatal("source redaction must be limited to its derived context")
	}
	if !SourceRedactionEnabled(WithSourceRedaction(derived)) {
		t.Fatal("nested source redaction lost its opt-in")
	}
}

func TestSourceRedactionPreservesDeadlineAndCancellation(t *testing.T) {
	deadline := time.Now().Add(time.Minute)
	parent, cancel := context.WithDeadline(context.Background(), deadline)
	derived := WithSourceRedaction(parent)
	if actual, ok := derived.Deadline(); !ok || !actual.Equal(deadline) {
		t.Fatal("source redaction changed its caller deadline")
	}
	cancel()
	if derived.Err() != context.Canceled {
		t.Fatal("source redaction lost caller cancellation")
	}
}
