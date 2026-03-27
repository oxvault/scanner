# Scanner Development Log

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
