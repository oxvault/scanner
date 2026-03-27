package providers

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
