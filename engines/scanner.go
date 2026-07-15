package engines

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/oxvault/scanner/providers"
)

// ScanOptions configures a scan run
type ScanOptions struct {
	SkipSAST     bool   // Skip source code analysis
	SkipDepAudit bool   // Skip dependency manifest audit
	SkipManifest bool   // Skip tool description analysis
	SkipEgress   bool   // Skip network egress detection
	ProbeNetwork bool   // Run runtime network probe after static scan
	FailOn       string // Exit non-zero at this severity: critical, high, warning

	// AIBOM sub-provider toggles. When set, findings produced by the
	// matching sub-provider are dropped after the composer returns. The
	// composer itself remains untouched — keeping skip behaviour purely
	// at the engine layer mirrors how SkipSAST / SkipManifest are
	// implemented for MCP scans and avoids re-wiring the composer per
	// scan. See filterAIBOMFindings for the exact rule-prefix mapping.
	SkipPickle      bool // Drop aibom-pickle-* findings
	SkipONNX        bool // Drop aibom-onnx-* findings
	SkipSafetensors bool // Drop aibom-safetensors-* findings
	SkipModelCard   bool // Drop aibom-modelcard-* findings
	SkipSignature   bool // Drop aibom-signature-* findings
}

// ScanReport holds the results of a scan
type ScanReport struct {
	Target     string
	Package    *providers.ResolvedPackage
	Tools      []providers.MCPTool
	Findings   []providers.Finding
	Suppressed []providers.Finding
}

// HasSeverity checks if the report contains findings at or above the given severity
func (r *ScanReport) HasSeverity(level string) bool {
	var threshold providers.Severity
	switch level {
	case "critical":
		threshold = providers.SeverityCritical
	case "high":
		threshold = providers.SeverityHigh
	case "warning":
		threshold = providers.SeverityWarning
	case "info":
		threshold = providers.SeverityInfo
	default:
		threshold = providers.SeverityCritical
	}

	for _, f := range r.Findings {
		if f.Severity >= threshold {
			return true
		}
	}
	return false
}

// ScannerEngine orchestrates a full security scan of an MCP server
type ScannerEngine interface {
	Scan(target string, opts ScanOptions) (*ScanReport, error)
}

type scanner struct {
	resolver      providers.Resolver
	mcpClient     providers.MCPClient
	ruleMatcher   providers.RuleMatcher
	sastAnalyzer  providers.SASTAnalyzer
	depAuditor    providers.DepAuditor
	hookAnalyzer  providers.HookAnalyzer
	reporter      providers.Reporter
	suppressor    providers.Suppressor
	netProbe      providers.NetProbe      // optional — nil if not wired
	aibomComposer providers.AIBOMComposer // optional — nil falls back to MCP-only behaviour
	logger        *slog.Logger
}

// NewScanner constructs the production ScannerEngine.
//
// The AIBOMComposer is optional: callers that build the engine without one
// can still scan MCP servers, but model-artifact / model-directory targets
// will surface a "no composer wired" error instead of a panic. App
// container always wires the composer in InitEngines, so the nil branch
// is reserved for unit tests that exercise the MCP-only flow.
func NewScanner(
	resolver providers.Resolver,
	mcpClient providers.MCPClient,
	ruleMatcher providers.RuleMatcher,
	sastAnalyzer providers.SASTAnalyzer,
	depAuditor providers.DepAuditor,
	hookAnalyzer providers.HookAnalyzer,
	reporter providers.Reporter,
	suppressor providers.Suppressor,
	netProbe providers.NetProbe,
	aibomComposer providers.AIBOMComposer,
	logger *slog.Logger,
) ScannerEngine {
	return &scanner{
		resolver:      resolver,
		mcpClient:     mcpClient,
		ruleMatcher:   ruleMatcher,
		sastAnalyzer:  sastAnalyzer,
		depAuditor:    depAuditor,
		hookAnalyzer:  hookAnalyzer,
		reporter:      reporter,
		suppressor:    suppressor,
		netProbe:      netProbe,
		aibomComposer: aibomComposer,
		logger:        logger,
	}
}

func (s *scanner) Scan(target string, opts ScanOptions) (*ScanReport, error) {
	report := &ScanReport{Target: target}

	// Step 1: Resolve target to local files
	s.logger.Info("resolving target", "target", target)
	pkg, err := s.resolver.Resolve(target)
	if err != nil {
		return nil, fmt.Errorf("resolve: %w", err)
	}
	report.Package = pkg

	// Remote resolvers stage the artifact in a temp dir — remove it on return
	// so untrusted code isn't left on disk. Local paths / HF cache: no TempDir.
	if pkg.TempDir != "" {
		defer func() {
			if rmErr := os.RemoveAll(pkg.TempDir); rmErr != nil {
				s.logger.Warn("failed to remove scan temp dir", "dir", pkg.TempDir, "error", rmErr)
			}
		}()
	}

	// AIBOM dispatch — model artifacts and model directories run through
	// the AIBOMComposer instead of the MCP-server pipeline. MCP-server
	// scanning over model weights would produce nonsense findings (every
	// pickle byte sequence looks like a "command injection" to the SAST
	// patterns), so we never fall through to the MCP path for these kinds.
	switch pkg.Kind {
	case providers.KindModelArtifact, providers.KindModelDirectory:
		return s.scanModelArtifact(report, pkg, opts)
	}

	// Step 2: Static analysis on source code
	if !opts.SkipSAST {
		s.logger.Info("running source code analysis", "path", pkg.Path)
		sastFindings := s.sastAnalyzer.AnalyzeDirectory(pkg.Path)
		report.Findings = append(report.Findings, sastFindings...)
		s.logger.Info("source code analysis complete", "findings", len(sastFindings))
	}

	// Step 3: Dependency audit (package.json, requirements.txt, pyproject.toml)
	if !opts.SkipDepAudit {
		s.logger.Info("running dependency audit", "path", pkg.Path)
		depFindings := s.depAuditor.AuditDirectory(pkg.Path)
		report.Findings = append(report.Findings, depFindings...)
		s.logger.Info("dependency audit complete", "findings", len(depFindings))
	}

	// Step 4: Install hook analysis (npm lifecycle scripts, PyPI cmdclass overrides)
	if !opts.SkipDepAudit && s.hookAnalyzer != nil {
		s.logger.Info("running install hook analysis", "path", pkg.Path)
		hookFindings := s.hookAnalyzer.AnalyzeDirectory(pkg.Path)
		report.Findings = append(report.Findings, hookFindings...)
		s.logger.Info("install hook analysis complete", "findings", len(hookFindings))
	}

	// Step 5: Network egress detection
	if !opts.SkipEgress {
		s.logger.Info("detecting network egress patterns")
		egressFindings := s.sastAnalyzer.DetectEgress(pkg.Path)
		for _, ef := range egressFindings {
			report.Findings = append(report.Findings, providers.Finding{
				Rule:     "mcp-network-egress",
				Severity: providers.SeverityWarning,
				Message:  fmt.Sprintf("Tool makes outbound network call via %s", ef.Method),
				File:     ef.File,
				Line:     ef.Line,
			})
		}
	}

	// Step 6: Connect to MCP server and get tool descriptions
	if !opts.SkipManifest && pkg.Command != "" {
		s.logger.Info("connecting to MCP server", "cmd", pkg.Command)
		session, err := s.mcpClient.Connect(pkg.Command, pkg.Args)
		if err != nil {
			s.logger.Warn("could not connect to MCP server — skipping manifest analysis", "error", err)
		} else {
			defer func() { _ = s.mcpClient.Close(session) }()

			tools, err := s.mcpClient.ListTools(session)
			if err != nil {
				s.logger.Warn("could not list tools", "error", err)
			} else {
				report.Tools = tools

				// Step 6: Scan each tool description
				for _, tool := range tools {
					descFindings := s.ruleMatcher.ScanDescription(tool.Description)
					for i := range descFindings {
						descFindings[i].Tool = tool.Name
					}
					report.Findings = append(report.Findings, descFindings...)

					// Step 7: Classify risk tier
					sourceCode := "" // TODO: map tool to source code function
					tier := s.ruleMatcher.ClassifyTool(tool, sourceCode)
					if tier >= providers.RiskTierHigh {
						severity := providers.SeverityWarning
						if tier == providers.RiskTierCritical {
							severity = providers.SeverityHigh
						}
						report.Findings = append(report.Findings, providers.Finding{
							Rule:     "mcp-sensitive-exposure",
							Severity: severity,
							Message:  fmt.Sprintf("Tool %q exposes %s-risk capabilities", tool.Name, tier),
							Tool:     tool.Name,
						})
					}

					// Step 8: Scan nested descriptions in input schema
					schemaDescs := extractSchemaDescriptions(tool.InputSchema)
					for _, desc := range schemaDescs {
						nestedFindings := s.ruleMatcher.ScanDescription(desc)
						for i := range nestedFindings {
							nestedFindings[i].Tool = tool.Name
							nestedFindings[i].Message = "[nested schema] " + nestedFindings[i].Message
						}
						report.Findings = append(report.Findings, nestedFindings...)
					}
				}
			}
		}
	}

	// Step N: Runtime network probe (optional — runs after all static analysis)
	if opts.ProbeNetwork && pkg.Command != "" {
		if s.netProbe == nil {
			s.logger.Warn("--probe-network requested but no NetProbe wired; skipping")
		} else {
			s.logger.Info("running runtime network probe", "cmd", pkg.Command)
			activities, probeErr := s.netProbe.Probe(pkg.Command, pkg.Args, 30*time.Second)
			if probeErr != nil {
				s.logger.Warn("network probe failed — skipping probe findings", "error", probeErr)
			} else {
				probeFindings := providers.NetActivityToFindings(activities)
				s.logger.Info("network probe complete",
					"connections", len(activities),
					"findings", len(probeFindings),
				)
				report.Findings = append(report.Findings, probeFindings...)
			}
		}
	}

	// Final step: apply suppression rules (.oxvaultignore + inline comments)
	if s.suppressor != nil && report.Package != nil {
		if err := s.suppressor.LoadIgnoreFile(report.Package.Path); err != nil {
			s.logger.Warn("could not load .oxvaultignore", "error", err)
		}
		kept, suppressed := s.suppressor.Filter(report.Findings)
		report.Findings = kept
		report.Suppressed = suppressed
		s.logger.Info("suppression applied",
			"kept", len(kept),
			"suppressed", len(suppressed),
		)
	}

	s.logger.Info("scan complete", "findings", len(report.Findings))
	return report, nil
}

// scanModelArtifact runs the AIBOM composer over a model artifact / model
// directory target and applies the same suppression + report shape used by
// MCP-server scans. Day 9 of the v0.4 AIBOM milestone — replaces the
// pre-wire stub that returned a "wire-up coming" error.
//
// Path selection mirrors the resolver's contract:
//
//   - For KindModelArtifact, the resolver places the parent directory in
//     pkg.Path and the absolute artifact filename in pkg.Args[0]. We hand
//     the artifact path to the composer so it dispatches to a single
//     sub-provider (no walk).
//   - For KindModelDirectory, the resolver leaves pkg.Path pointing at the
//     directory itself. The composer walks it, dispatches every recognised
//     file, and runs cross-file aggregation (missing-card, signature
//     verification per artifact).
//
// Skip-flag enforcement happens AFTER the composer returns: filterAIBOMFindings
// drops findings whose Rule prefix matches a skipped sub-provider. That keeps
// the composer untouched and matches how SkipSAST / SkipManifest are
// implemented for MCP scans.
//
// The named return is load-bearing only insofar as suppression mutates
// report.Findings via append — the function does not panic-recover, since
// every sub-provider already wraps its own panics (Day 5 onnx, Day 6
// modelcard, Day 7 signature).
func (s *scanner) scanModelArtifact(report *ScanReport, pkg *providers.ResolvedPackage, opts ScanOptions) (*ScanReport, error) {
	if s.aibomComposer == nil {
		return nil, fmt.Errorf(
			"no AIBOMComposer wired — cannot scan %s target %q (build the engine via app.NewApp so InitEngines wires the composer)",
			pkg.Kind, pkg.Path,
		)
	}

	target := pkg.Path
	if pkg.Kind == providers.KindModelArtifact && len(pkg.Args) > 0 && pkg.Args[0] != "" {
		// The resolver re-attaches the absolute artifact path to Args[0]
		// for single-file targets. Prefer that over pkg.Path (which points
		// at the parent directory) so the composer dispatches to one
		// sub-provider rather than walking the whole directory.
		target = pkg.Args[0]
	}

	s.logger.Info("running AIBOM composer", "target", target, "kind", pkg.Kind)
	findings := s.aibomComposer.Scan(target)
	s.logger.Info("AIBOM composer complete", "findings", len(findings))

	findings = filterAIBOMFindings(findings, opts)
	report.Findings = append(report.Findings, findings...)

	// Apply suppression — same path as the MCP flow. The .oxvaultignore
	// file is read from the artifact's directory so model authors can ship
	// scoped suppressions next to their weights without touching their
	// MCP server config.
	if s.suppressor != nil && report.Package != nil {
		ignoreDir := report.Package.Path
		if err := s.suppressor.LoadIgnoreFile(ignoreDir); err != nil {
			s.logger.Warn("could not load .oxvaultignore", "error", err)
		}
		kept, suppressed := s.suppressor.Filter(report.Findings)
		report.Findings = kept
		report.Suppressed = suppressed
		s.logger.Info("suppression applied",
			"kept", len(kept),
			"suppressed", len(suppressed),
		)
	}

	s.logger.Info("scan complete", "findings", len(report.Findings))
	return report, nil
}

// filterAIBOMFindings drops findings produced by sub-providers the user
// asked to skip. The mapping is by rule-id prefix:
//
//	aibom-pickle-*       → SkipPickle
//	aibom-onnx-*         → SkipONNX
//	aibom-safetensors-*  → SkipSafetensors
//	aibom-modelcard-*    → SkipModelCard
//	aibom-signature-*    → SkipSignature
//
// Findings that do not match any AIBOM prefix (e.g. aibom-clean,
// aibom-unknown-format) are always preserved — skip flags only gate the
// per-sub-provider rule families.
func filterAIBOMFindings(findings []providers.Finding, opts ScanOptions) []providers.Finding {
	if !opts.SkipPickle && !opts.SkipONNX && !opts.SkipSafetensors && !opts.SkipModelCard && !opts.SkipSignature {
		return findings
	}
	out := make([]providers.Finding, 0, len(findings))
	for _, f := range findings {
		switch {
		case opts.SkipPickle && hasPrefix(f.Rule, "aibom-pickle-"):
			continue
		case opts.SkipONNX && hasPrefix(f.Rule, "aibom-onnx-"):
			continue
		case opts.SkipSafetensors && hasPrefix(f.Rule, "aibom-safetensors-"):
			continue
		case opts.SkipModelCard && hasPrefix(f.Rule, "aibom-modelcard-"):
			continue
		case opts.SkipSignature && hasPrefix(f.Rule, "aibom-signature-"):
			continue
		}
		out = append(out, f)
	}
	return out
}

// hasPrefix is a tiny inlinable helper used by filterAIBOMFindings. We
// intentionally avoid importing strings just for one HasPrefix call — keep
// the engine package's import surface as narrow as possible.
func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// extractSchemaDescriptions walks a JSON Schema and extracts all description fields
func extractSchemaDescriptions(schema map[string]any) []string {
	var descs []string
	extractDescriptionsRecursive(schema, &descs, 0, 20)
	return descs
}

func extractDescriptionsRecursive(obj map[string]any, descs *[]string, depth, maxDepth int) {
	if depth > maxDepth {
		return
	}

	if desc, ok := obj["description"].(string); ok {
		*descs = append(*descs, desc)
	}

	for _, v := range obj {
		switch val := v.(type) {
		case map[string]any:
			extractDescriptionsRecursive(val, descs, depth+1, maxDepth)
		case []any:
			for _, item := range val {
				if m, ok := item.(map[string]any); ok {
					extractDescriptionsRecursive(m, descs, depth+1, maxDepth)
				}
			}
		}
	}
}
