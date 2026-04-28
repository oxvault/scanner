# Scanner Development Log

## Day 7 — Signature verifier — 2026-04-27

Branch: `feat/aibom-day7-signature`

### What shipped
- `providers/signature.go` — `SignatureVerifier` provider that verifies ML model artifacts against the OpenSSF Model Signing JSON manifest format (`model_signing.json`)
- Hash-only verification for v0.4 — full Sigstore Rekor/Fulcio + OIDC chain verification deferred to v0.4.1. Sigstore bundles (`.sigstore`) get presence + JSON-shape + spec-shaped-keys checks; loose detached signatures (`.sig`) get presence-only checks
- `WithTrustedIssuers([]string)` REPLACES the default OIDC issuer allowlist; `WithAdditionalTrustedIssuers([]string)` MERGES with defaults. Issuer URLs are canonicalised (lowercase scheme/host, trailing slash trimmed) at construction and at verification so case-only and trailing-slash differences don't fire spurious untrusted-issuer findings
- Streaming SHA-256 (`io.Copy(sha256.New(), f)`) — multi-GB checkpoints don't OOM the scanner
- 256 KiB cap on manifest + bundle reads (`patterns.MaxSignatureManifestBytes`) so a hostile producer can't drown the JSON parser
- `defer recover()` with named return — same panic-safety pattern locked in during Day 5 onnx and Day 6 modelcard
- Cross-file aggregation lives in `AIBOMComposer.Scan()`: every model artifact (`.pkl` / `.pt` / `.onnx` / `.safetensors`) gets a `signature.VerifyArtifact(path)` call after the per-file dispatch, mirroring the missing-card aggregation pattern. Single-file scans ALSO run signature verification (with `aibom-signature-missing` filtered out) so the canonical sign-then-tamper attack fires on `oxvault scan ./tampered.pkl`

### v0.4 trust posture (post pre-merge review)

The v0.4 verifier performs **hash-only** verification. The manifest's `issuer` field is **self-declared** by whoever wrote the manifest — there is no cryptographic chain proving who signed. The rule IDs reflect that posture honestly:

- `aibom-signature-hash-match` (INFO) — manifest hash matches artifact, issuer is in the trusted-issuer list, but the issuer claim is **self-declared**. v0.4.1 will perform Rekor/Fulcio chain verification and promote successful runs to `aibom-signature-clean`.
- `aibom-signature-presence-deferred` (INFO) — sigstore bundle or loose `.sig` present alongside artifact; cryptographic verification deferred to v0.4.1.
- `aibom-signature-clean` (INFO) — **RESERVED for v0.4.1**. v0.4 must NOT emit this rule. The `TestSignatureVerifier_CleanRuleNeverEmittedInV04` test pins the contract.

### Rule IDs
| Rule | Severity | Trigger | CWE |
| --- | --- | --- | --- |
| `aibom-signature-hash-match` | INFO | v0.4: manifest hash matches + issuer trusted (self-declared) | — |
| `aibom-signature-presence-deferred` | INFO | sigstore bundle / .sig present; crypto deferred to v0.4.1 | — |
| `aibom-signature-clean` | INFO | RESERVED for v0.4.1 OIDC-verified path | — |
| `aibom-signature-missing` | WARNING | no signature carrier alongside artifact | CWE-347 |
| `aibom-signature-invalid` | CRITICAL | manifest present but does not list this artifact | CWE-347 |
| `aibom-signature-untrusted-issuer` | HIGH | manifest issuer empty or not in configured trusted set | CWE-347 |
| `aibom-signature-hash-mismatch` | CRITICAL | manifest SHA-256 != actual artifact SHA-256 | CWE-353 |
| `aibom-signature-malformed-manifest` | WARNING | manifest JSON parse fails / size cap exceeded / declared hash not hex64 / panic | CWE-20 |
| `aibom-signature-malformed-bundle` | WARNING | sigstore bundle missing all spec-shaped top-level keys (mediaType, messageSignature, verificationMaterial, dsseEnvelope) | CWE-345 |

### Key design decisions
- **Pure stdlib crypto:** `crypto/sha256`, `encoding/hex`, `encoding/base64`, `encoding/json`. NO Sigstore SDK, NO protobuf bindings. The Sigstore SDK is a Day 8+ decision and would land in v0.4.1 alongside Rekor/Fulcio verification.
- **Verifier-looks-for-paired-files:** the composer dispatches per-file by `ArtifactFormat`. Rather than wire artifact↔signature pairing into the dispatcher (which would mean two arguments to `VerifyArtifact`), the verifier itself looks in the artifact's directory for `model_signing.json`, `<artifact>.sigstore`, or `<artifact>.sig`. Matches the modelcard-checker aggregation pattern. Single-argument interface stays clean.
- **`manifest.json` dropped from `SignatureManifestNames`:** too generic — npm and OCI build tools produce a bare `manifest.json` for unrelated reasons. Honouring it would let an attacker spoof a missing-signature finding by dropping any random JSON file named `manifest.json` next to a tampered artifact. Only the OpenSSF spec basename `model_signing.json` is recognised.
- **WithTrustedIssuers REPLACES, WithAdditionalTrustedIssuers MERGES:** the REPLACE-by-default semantics surprised users in the pre-merge review, so the merge variant is now the safer recommended option for "I want defaults plus my corp issuer". WithTrustedIssuers is documented loudly as REPLACE.
- **Carrier priority — manifest > .sigstore > .sig, all evaluated:** when multiple carriers are present, the verifier evaluates ALL of them and merges findings. An attacker dropping a 1-byte `.sig` next to a tampered artifact can no longer shadow the manifest's hash-mismatch CRITICAL — every present carrier contributes its own findings, and the reporter promotes the verdict to the highest severity.
- **Sigstore bundle requires spec-shaped content:** an empty `{}` or any random JSON object is rejected as `aibom-signature-malformed-bundle`. The bundle must contain at least one of the Sigstore Bundle proto's top-level keys (`mediaType`, `messageSignature`, `verificationMaterial`, `dsseEnvelope`).
- **Declared SHA-256 must be hex64 BEFORE equality:** attacker-controlled garbage (terminal escapes, shell metacharacters) in the manifest's `sha256` field is rejected as `aibom-signature-malformed-manifest` before any string flows into `Finding.Message`. Defence in depth against log-injection style attacks where the attacker's manifest controls part of our reporter output.
- **Carriers no-op when dispatched directly:** when the composer dispatches a `.sigstore` / `.sig` file via `FormatSignature`, `VerifyArtifact` returns nil. Signatures are evaluated FROM the artifact's perspective only — handing the verifier a carrier directly would otherwise double-count when the composer's walk reaches both the carrier and the artifact in the same directory.
- **Single-file scans run verification but suppress `-missing`:** `composer.Scan(./tampered.pkl)` runs full signature verification and DOES emit hash-mismatch CRITICAL when a sibling manifest declares the wrong hash — the canonical sign-then-tamper attack. Only `aibom-signature-missing` is filtered, mirroring the missing-card convention (the user is targeting an artifact in isolation, not declaring "this directory should have a signature").

### Files
- `providers/signature.go` (real implementation, replaces Day 1 skeleton)
- `providers/signature_test.go` (fixture suite + synthesised edge cases + composer integration + trust-bypass regression suite)
- `providers/aibom_composer.go` (composer drives signature aggregation; single-file branch also runs signature verification)
- `providers/aibom_composer_test.go` (updated VerifyArtifactCount expectation: 1 dispatch + 3 aggregation)
- `patterns/aibom.go` (signature manifest constants, trusted issuer list, sigstore-bundle spec keys, ext patterns; `manifest.json` dropped from `SignatureManifestNames`)
- `scripts/gen_aibom_fixtures.py` (extended with 6 signature fixtures)
- `testdata/aibom/signature/` (safe + malicious fixtures)

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
