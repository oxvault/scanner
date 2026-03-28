# Scanner Development Log

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
