package detectors

import "context"

type sourceRedactionKey struct{}

// WithSourceRedaction requests additional credential components needed to edit
// original source. Ordinary scan results retain their upstream SecretParts so
// adding source redaction does not expose extra secrets in scanner output.
// It does not enable verification or modify cancellation and deadlines.
func WithSourceRedaction(ctx context.Context) context.Context {
	return context.WithValue(ctx, sourceRedactionKey{}, true)
}

// SourceRedactionEnabled reports whether source editing explicitly requested
// additional sensitive components. It is disabled by default.
func SourceRedactionEnabled(ctx context.Context) bool {
	enabled, _ := ctx.Value(sourceRedactionKey{}).(bool)
	return enabled
}
