package providers

// SetONNXPanicHookForTest installs (or clears, when fn is nil) the panic hook
// invoked at the start of validateOnnxFile's wire walk. This exists so that
// tests in the providers_test package can verify the deferred recover() in
// validateOnnxFile correctly surfaces panic-derived findings to callers via
// the named return. The seam is unused in production builds.
func SetONNXPanicHookForTest(fn func()) {
	onnxPanicHookForTest = fn
}

// EffectivePickleMaxBytes exposes the analyzer's resolved max-file cap to
// tests in the providers_test package. Only used to verify that
// WithPickleMaxFileBytes clamps values per the documented contract.
func EffectivePickleMaxBytes(p PickleAnalyzer) int64 {
	if pa, ok := p.(*pickleAnalyzer); ok {
		return pa.effectiveMaxBytes()
	}
	return -1
}

// PickleMaxFileBytesCeiling is the hard ceiling that WithPickleMaxFileBytes
// clamps user input down to. Exported for assertion in clamp tests.
func PickleMaxFileBytesCeiling() int64 {
	return int64(maxFileBytes)
}

