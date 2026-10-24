// trufflehog-redact retains the standalone source-redaction interface.
package main

import (
	"fmt"
	"os"

	"github.com/trufflesecurity/trufflehog/v3/internal/sourceredact"
)

func main() {
	if err := sourceredact.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "source redaction failed:", err)
		os.Exit(1)
	}
}
