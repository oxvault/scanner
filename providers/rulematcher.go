package providers

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/oxvault/scanner/patterns"
)

type ruleMatcher struct{}

func NewRuleMatcher() RuleMatcher {
	return &ruleMatcher{}
}

func (r *ruleMatcher) ScanDescription(description string) []Finding {
	var findings []Finding

	// Pattern-based checks
	for _, p := range patterns.DescriptionPatterns {
		matches := p.Pattern.FindStringSubmatch(description)
		if len(matches) > 0 {
			msg := p.Message
			if strings.Contains(msg, "%s") {
				matched := matches[0]
				if len(matched) > 100 {
					matched = matched[:100] + "..."
				}
				msg = fmt.Sprintf(msg, matched)
			}
			confidence := p.Confidence
			if confidence == 0 {
				confidence = ConfidenceMedium
			}
			findings = append(findings, Finding{
				Rule:            p.Rule,
				Severity:        p.Severity,
				Confidence:      confidence,
				ConfidenceLabel: confidence.String(),
				Message:         msg,
				CWE:             p.CWE,
			})
		}
	}

	// Unicode invisible character detection
	if invisibleFindings := detectInvisibleChars(description); len(invisibleFindings) > 0 {
		findings = append(findings, invisibleFindings...)
	}

	return findings
}

func (r *ruleMatcher) ScanArguments(args map[string]any) []Finding {
	var findings []Finding

	for key, val := range args {
		strVal, ok := val.(string)
		if !ok {
			continue
		}

		for _, p := range patterns.ArgumentPatterns {
			if p.Pattern.MatchString(strVal) {
				matched := strVal
				if len(matched) > 80 {
					matched = matched[:80] + "..."
				}
				findings = append(findings, Finding{
					Rule:            p.Rule,
					Severity:        p.Severity,
					Confidence:      ConfidenceMedium,
					ConfidenceLabel: ConfidenceMedium.String(),
					Message:         fmt.Sprintf(p.Message, matched),
					Tool:            key,
					CWE:             p.CWE,
				})
			}
		}
	}

	return findings
}

func (r *ruleMatcher) ScanResponse(response string) []Finding {
	var findings []Finding

	for _, p := range patterns.ResponsePatterns {
		if p.Pattern.MatchString(response) {
			findings = append(findings, Finding{
				Rule:            p.Rule,
				Severity:        p.Severity,
				Confidence:      ConfidenceHigh,
				ConfidenceLabel: ConfidenceHigh.String(),
				Message:         p.Message,
				CWE:             p.CWE,
			})
		}
	}

	return findings
}

func (r *ruleMatcher) ClassifyTool(tool MCPTool, sourceCode string) RiskTier {
	desc := strings.ToLower(tool.Description)
	src := strings.ToLower(sourceCode)
	combined := desc + " " + src

	// Tier 1 — Critical: shell execution, code eval
	for _, p := range patterns.Tier1Keywords {
		if strings.Contains(combined, p) {
			return RiskTierCritical
		}
	}

	// Tier 2 — High: filesystem, database, infrastructure
	for _, p := range patterns.Tier2Keywords {
		if strings.Contains(combined, p) {
			return RiskTierHigh
		}
	}

	// Tier 3 — Medium: network requests, messaging
	for _, p := range patterns.Tier3Keywords {
		if strings.Contains(combined, p) {
			return RiskTierMedium
		}
	}

	// Tier 4 — Low: compute-only
	return RiskTierLow
}

// detectInvisibleChars scans for Unicode invisible characters used in steganography
func detectInvisibleChars(text string) []Finding {
	var findings []Finding
	var invisibleCount int

	for _, r := range text {
		if isInvisibleChar(r) {
			invisibleCount++
		}
	}

	if invisibleCount > 0 {
		findings = append(findings, Finding{
			Rule:            "mcp-unicode-injection",
			Severity:        SeverityCritical,
			Confidence:      ConfidenceMedium,
			ConfidenceLabel: ConfidenceMedium.String(),
			Message:         fmt.Sprintf("Found %d invisible Unicode characters in tool description (possible steganographic payload)", invisibleCount),
			CWE:             "CWE-116",
		})
	}

	// Check for Unicode Tags block (U+E0000-E007F) — most dangerous
	for _, r := range text {
		if r >= 0xE0000 && r <= 0xE007F {
			findings = append(findings, Finding{
				Rule:            "mcp-unicode-tags-block",
				Severity:        SeverityCritical,
				Confidence:      ConfidenceHigh,
				ConfidenceLabel: ConfidenceHigh.String(),
				Message:         "Unicode Tags block characters detected — hidden ASCII message embedded in description",
				CWE:             "CWE-116",
			})
			break
		}
	}

	return findings
}

func isInvisibleChar(r rune) bool {
	// Zero-width characters
	if r >= 0x200B && r <= 0x200F {
		return true
	}
	// Line/paragraph separators
	if r == 0x2028 || r == 0x2029 {
		return true
	}
	// BiDi controls
	if r >= 0x202A && r <= 0x202E {
		return true
	}
	// Word joiner and invisible separators
	if r >= 0x2060 && r <= 0x2064 {
		return true
	}
	// BOM
	if r == 0xFEFF {
		return true
	}
	// Unicode Tags block
	if r >= 0xE0000 && r <= 0xE007F {
		return true
	}
	// Variation selectors
	if r >= 0xFE00 && r <= 0xFE0F {
		return true
	}
	// Check general category
	if unicode.Is(unicode.Cf, r) {
		return true
	}
	return false
}
