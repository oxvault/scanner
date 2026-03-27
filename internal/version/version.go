// Package version holds the single source of truth for the scanner version.
package version

// Version is the canonical version string. Override at build time with:
//
//	go build -ldflags "-X github.com/oxvault/scanner/internal/version.Version=x.y.z"
var Version = "0.1.0"
