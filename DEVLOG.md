# Scanner Development Log

## Day 6 — Model card checker — 2026-04-27

Branch: `feat/aibom-day6-modelcard`

### What shipped
- `providers/modelcard.go` — `ModelCardChecker` provider that inspects HuggingFace / OpenSSF model cards (`README.md`, `MODEL_CARD.md`, `model_card.yaml`, `.modelcard.yaml`)
- YAML frontmatter splitter with BOM tolerance, CRLF tolerance, and unbalanced-opener detection
- Body-injection scanning is delegated to the existing `RuleMatcher.ScanDescription` (no duplicate pattern lists in the model-card layer) — the same detector that scans MCP tool descriptions catches prompt-injection in card markdown
- Cross-file aggregation lives in `AIBOMComposer.Scan()`: any directory containing a model artifact (`.pkl` / `.pt` / `.onnx` / `.safetensors`) without a model card alongside it emits `aibom-modelcard-missing` end-to-end on real `oxvault scan` invocations
- `bodyMentionsSource` requires HuggingFace dataset/model paths, arXiv refs, or section headers — bare `github.com/` / `paperswithcode.com/` / `kaggle.com/` no longer suppresses the no-source rule (was too permissive)
- `defer recover()` in `checkFile` for parity with `onnx.go` / `pickle.go` — a panic during YAML unmarshal or RuleMatcher dispatch surfaces as a `aibom-modelcard-malformed-yaml` WARNING instead of crashing the scanner

### Rule IDs (post review-split)
| Rule | Severity | Trigger |
| --- | --- | --- |
| `aibom-modelcard-clean` | INFO | all checks passed |
| `aibom-modelcard-no-license` | WARNING | no license declared |
| `aibom-modelcard-no-source` | WARNING | no provenance declared |
| `aibom-modelcard-no-eval` | INFO | uncited benchmark claim |
| `aibom-modelcard-suspicious-instructions` | HIGH | prompt-injection in body |
| `aibom-modelcard-malformed-yaml` | WARNING | YAML parse failure |
| `aibom-modelcard-too-large` | WARNING | exceeds `MaxModelCardFileBytes` (1 MiB) |
| `aibom-modelcard-empty` | WARNING | zero-byte file |
| `aibom-modelcard-missing` | WARNING | artifact directory has no card |

### Key design decisions
- **Dependency:** `gopkg.in/yaml.v3` (already in scanner go.mod for other YAML use)
- **RuleMatcher delegation:** model-card checker accepts an injected `RuleMatcher` via `WithModelCardCheckerRuleMatcher`, falling back to a fresh `NewRuleMatcher()`. Composer can share its RuleMatcher across providers for consistent detection state.
- **Missing-card aggregation in composer:** the previous design had `CheckDirectory` aggregate, but the composer dispatches per-file via `WalkScanFiles` and never called `CheckDirectory` — the rule was dead in production. Aggregation now lives in `composer.Scan` and uses a shared `missingCardFindings` helper so `CheckDirectory` (still on the interface for direct callers) stays consistent.
- **Rule-ID split:** review fix — `malformed-yaml` was overloaded with too-large + empty signals. Split into three distinct rule IDs so users can filter "this card is just oversized" from "this card has a YAML parse error" from "this card is empty".

### Files
- `providers/modelcard.go` (new + this PR's edits)
- `providers/aibom_composer.go` (composer drives missing-card aggregation)
- `providers/modelcard_test.go` (rule-ID split tests, panic-recovery test, tightened `bodyMentionsSource` tests)
- `providers/aibom_composer_test.go` (end-to-end missing-card integration tests)
- `patterns/aibom.go` (model-card constants and regexes)
- `testdata/aibom/modelcard/` (safe + malicious fixtures)

## v0.3.3 — 2026-03-27

### Patterns package
- Extracted all detection pattern lists to a dedicated `patterns/` package (19 lists, 6 files)
- `patterns/` is a leaf node — pure data, no imports from the rest of the codebase

### Code quality
- Removed all type assertions — replaced with proper type guards throughout
- Shared `isExcludedDir` helper extracted (was duplicated across providers)
- Regex patterns hoisted to package-level `var` blocks (compiled once, not per-call)
- `scanFileWithPatterns` helper introduced — DRY wrapper for the per-file SAST loop
- `walkSourceFiles` helper introduced — single place for directory walk + exclusion logic
- Version is now the single source of truth in `internal/version/version.go`
- Truncation dedup: identical truncated findings are now collapsed before reporting

### Version reporting
- ldflags wired in Makefile (`-X github.com/oxvault/scanner/internal/version.Version`)
- GoReleaser `ldflags` path updated to match `internal/version/version.go`
- Double-v display fixed (`v0.3.3` no longer printed as `vv0.3.3`)

### CLI fixes
- `pin` and `check` commands: flag parsing fixed with `SetInterspersed(false)` — flags after the command target are now passed through correctly

### README
- Examples updated to use real, published npm packages
- `--` separator documented for pass-through arguments to the MCP server

### Install script
- `oxvault.dev/install.sh` — curl-pipe install now live

### Validation
- 141-server sweep: 50% of servers had HIGH+ findings, 135 confirmed CRITICALs, 93% precision

## v0.3.2 — 2026-03-28
- Full 141-server validation sweep — 50% had HIGH+ findings, 135 confirmed CRITICALs (93% precision)
- Excluded dist/, build/, out/ directories (transpiled output)
- Excluded third_party/, third-party/ directories (vendored bundles)
- Excluded *-bundle.* and *_bundle.* files
- Skip JS/TS files with lines >1000 chars (bundled output detection)
- CRITICALs reduced from 37 to 13 on 67-server baseline (all 13 confirmed TPs)
- curl | sh install script added
- README updated with verified sweep numbers

## v0.3.1 — 2026-03-26
- Full validation sweep — 67 real MCP servers scanned
- False positive fixes — 30 confirmed FPs eliminated, 0 TPs lost
  - Word boundary on eval/exec patterns (16 AWS docstring FPs)
  - Allowlisted ast.literal_eval(), page.$eval(), page.$$eval()
  - Excluded private key headers in regex compilation contexts
  - Suppressed mock/fake/test placeholder credentials
  - Suppressed PascalCase type name credential values
  - Excluded eval/exec in quoted string literals
  - Expanded test file/directory detection
- Dependency exclusions — node_modules/, vendor/, .smithery/, .d.ts, .min.js, .bundle.js excluded from SAST
- 449 lines of regression tests added
- README updated with honest numbers

## v0.3.0 — 2026-03-25
- Confidence scoring — high/medium/low on every finding
- Real-world scan results added to README
- SAST false positive reduction (45% fewer actionable findings)

## v0.2.0 — 2026-03-23
- Suppression system — .oxvaultignore + inline oxvault:ignore comments
- Scan-action v1.0.2 with SARIF relative path fix
- GoReleaser Homebrew tap config (blocked on PAT)

## v0.1.1 — 2026-03-21
- Initial public release
- 60+ detection rules, 12/12 CVE detection, 0% FP
- 200+ tests, SARIF + JSON output, GitHub Action
