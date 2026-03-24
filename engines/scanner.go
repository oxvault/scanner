package engines

import (
	"fmt"
	"log/slog"

	"github.com/oxvault/scanner/providers"
)

// ScanOptions configures a scan run
type ScanOptions struct {
	SkipSAST     bool   // Skip source code analysis
	SkipManifest bool   // Skip tool description analysis
	SkipEgress   bool   // Skip network egress detection
	FailOn       string // Exit non-zero at this severity: critical, high, warning
}

// ScanReport holds the results of a scan
type ScanReport struct {
	Target   string
	Package  *providers.ResolvedPackage
	Tools    []providers.MCPTool
	Findings []providers.Finding
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
	resolver     providers.Resolver
	mcpClient    providers.MCPClient
	ruleMatcher  providers.RuleMatcher
	sastAnalyzer providers.SASTAnalyzer
	reporter     providers.Reporter
	logger       *slog.Logger
}

func NewScanner(
	resolver providers.Resolver,
	mcpClient providers.MCPClient,
	ruleMatcher providers.RuleMatcher,
	sastAnalyzer providers.SASTAnalyzer,
	reporter providers.Reporter,
	logger *slog.Logger,
) ScannerEngine {
	return &scanner{
		resolver:     resolver,
		mcpClient:    mcpClient,
		ruleMatcher:  ruleMatcher,
		sastAnalyzer: sastAnalyzer,
		reporter:     reporter,
		logger:       logger,
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

	// Step 2: Static analysis on source code
	if !opts.SkipSAST {
		s.logger.Info("running source code analysis", "path", pkg.Path)
		sastFindings := s.sastAnalyzer.AnalyzeDirectory(pkg.Path)
		report.Findings = append(report.Findings, sastFindings...)
		s.logger.Info("source code analysis complete", "findings", len(sastFindings))
	}

	// Step 3: Network egress detection
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

	// Step 4: Connect to MCP server and get tool descriptions
	if !opts.SkipManifest && pkg.Command != "" {
		s.logger.Info("connecting to MCP server", "cmd", pkg.Command)
		session, err := s.mcpClient.Connect(pkg.Command, pkg.Args)
		if err != nil {
			s.logger.Warn("could not connect to MCP server — skipping manifest analysis", "error", err)
		} else {
			defer s.mcpClient.Close(session)

			tools, err := s.mcpClient.ListTools(session)
			if err != nil {
				s.logger.Warn("could not list tools", "error", err)
			} else {
				report.Tools = tools

				// Step 5: Scan each tool description
				for _, tool := range tools {
					descFindings := s.ruleMatcher.ScanDescription(tool.Description)
					for i := range descFindings {
						descFindings[i].Tool = tool.Name
					}
					report.Findings = append(report.Findings, descFindings...)

					// Step 6: Classify risk tier
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

					// Step 7: Scan nested descriptions in input schema
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

	s.logger.Info("scan complete", "findings", len(report.Findings))
	return report, nil
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
