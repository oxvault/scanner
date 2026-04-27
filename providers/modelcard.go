package providers

// modelCardChecker is the Day-1 skeleton implementation. The real model-card
// section validator lands in Day 5 of the v0.4 AIBOM milestone.
type modelCardChecker struct{}

// NewModelCardChecker returns a ModelCardChecker.
func NewModelCardChecker() ModelCardChecker {
	return &modelCardChecker{}
}

// CheckFile is a no-op skeleton. Real logic arrives in Day 5.
func (m *modelCardChecker) CheckFile(_ string) []Finding {
	return nil
}

// CheckDirectory is a no-op skeleton. Real logic arrives in Day 5.
func (m *modelCardChecker) CheckDirectory(_ string) []Finding {
	return nil
}
