package providers

// SetONNXPanicHookForTest installs (or clears, when fn is nil) the panic hook
// invoked at the start of validateOnnxFile's wire walk. This exists so that
// tests in the providers_test package can verify the deferred recover() in
// validateOnnxFile correctly surfaces panic-derived findings to callers via
// the named return. The seam is unused in production builds.
func SetONNXPanicHookForTest(fn func()) {
	onnxPanicHookForTest = fn
}
