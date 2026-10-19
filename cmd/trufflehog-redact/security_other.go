//go:build !linux && !windows

package main

import (
	"errors"
	"os"
)

// Stdin redaction remains portable. In-place replacement is deliberately
// disabled until ownership, ACLs and security labels have a reviewed adapter.
type securityMetadata struct{}

func (securityMetadata) size() int64 { return 0 }
func captureSecurity(*os.File) (securityMetadata, error) {
	return securityMetadata{}, errors.New("in-place security metadata preservation is unsupported on this platform")
}
func sameSecurity(*os.File, securityMetadata) bool { return false }
func privateStaging(*os.File) error                { return errors.New("unsupported in-place platform") }
func applySecurity(*os.File, securityMetadata) error {
	return errors.New("unsupported in-place platform")
}
