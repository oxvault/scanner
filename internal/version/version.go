// Package version holds the single source of truth for the scanner version.
package version

// Version is the scanner version. Releases inject the git tag at build time
// (Makefile / GoReleaser ldflags); this "dev" default is what un-ldflagged
// builds (go run, go install) report — never a stale release number.
//
//	go build -ldflags "-X github.com/oxvault/scanner/internal/version.Version=x.y.z"
var Version = "dev"
