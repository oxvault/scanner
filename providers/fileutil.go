package providers

import (
	"os"
	"path/filepath"
)

// IsExcludedDir returns true when the directory should be entirely skipped
// during source analysis. It is the single source of truth for directory
// exclusion across all providers (SAST, dep-audit, hook-analyzer).
func IsExcludedDir(name string) bool {
	return isExcludedDir(name)
}

// IsExcludedFile returns true when the file should be skipped during source
// analysis regardless of its directory.
func IsExcludedFile(name string) bool {
	return isExcludedFile(name)
}

// WalkScanFiles walks dir, skipping excluded directories and files (per the
// shared isExcludedDir / isExcludedFile rules), and calls fn for every
// remaining regular file. Symlinks are NOT followed — filepath.Walk's default
// behaviour. Walk errors are swallowed so a single unreadable subdirectory
// never aborts the whole scan.
//
// This is the cross-provider equivalent of the unexported walkSourceFiles in
// sast.go; consumers that don't care about source-language detection (e.g.
// the AIBOM composer) should use this helper rather than re-rolling their own
// filepath.Walk.
func WalkScanFiles(dir string, fn func(path string)) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if isExcludedDir(filepath.Base(path)) {
				return filepath.SkipDir
			}
			return nil
		}
		if isExcludedFile(filepath.Base(path)) {
			return nil
		}
		fn(path)
		return nil
	})
}
