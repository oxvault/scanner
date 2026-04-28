# Scanner Development Log

## Day 10 — v0.4.0 release prep — 2026-04-28

Branch: `feat/aibom-day10-release`

### What shipped
- `examples/vulnerable-models/` — 5 demo dirs covering each AIBOM detection class (pickle RCE, safetensors overflow, ONNX malformed, model card poisoning, unsigned)
- Top-level `examples/vulnerable-models/README.md` explaining each pattern
- `Makefile` `scan-demo` target extended — now scans both vulnerable-servers AND vulnerable-models
- `internal/version/version.go` bumped to `v0.4.0`
- `CHANGELOG.md` created with full v0.4.0 release notes (rule IDs, CLI flags, deps, deferred work, breaking changes = none)

### v0.4.0 ships
- 5 new sub-providers (pickle, safetensors, onnx, modelcard, signature)
- ~38 new aibom-* detection rules
- Hugging Face resolver (`oxvault scan hf:org/model`)
- 8 new CLI flags
- 1 new dep (gopkg.in/yaml.v3)
- 0 breaking changes

### Test count
- ~672 tests passing across all packages (up from ~480 in v0.3.3)
- 25+ AIBOM binary fixtures in `testdata/aibom/`
- All quality gates green: `make build`, `make test`, `make lint`, `make scan-demo`

### Deferred
- v0.4.1: Sigstore Rekor/Fulcio chain verification, cross-resolve cache cap, ctx plumbing
- v0.5: RAG corpus scanning

---

## Day 9 — Engine wiring + CLI flag surface — 2026-04-28

Branch: `feat/aibom-day9-cli`

### What shipped
- **`engines/scanner.go`** — replaced the Day 1-8 placeholder error (`"AIBOM scanning lands in v0.4 — wire-up coming Day 9"`) with real dispatch. `KindModelArtifact` and `KindModelDirectory` packages now flow through `scanModelArtifact()` which calls `aibomComposer.Scan(target)`, applies skip-flag filtering, and runs the same suppression + report shape used by MCP scans. **`oxvault scan ./model.pkl`, `oxvault scan ./model-dir/`, and `oxvault scan hf:org/model` are all functional end-to-end.**
- **`engines.NewScanner`** — added `aibomComposer providers.AIBOMComposer` parameter (positioned after `netProbe`, before `logger`). Nil composer is allowed for tests that exercise the MCP-only flow; production wiring through `app.NewApp` always supplies one.
- **`engines.ScanOptions`** — added `SkipPickle`, `SkipONNX`, `SkipSafetensors`, `SkipModelCard`, `SkipSignature` bool fields. Filtering happens AFTER the composer returns by rule-prefix match (`aibom-pickle-*` etc.) — composer stays untouched, mirroring `SkipSAST` / `SkipManifest` semantics on the MCP side.
- **`app/app.go`** — added six AIBOM provider fields and getters (`pickleAnalyzer`, `onnxValidator`, `safetensorsValidator`, `modelCardChecker`, `signatureVerifier`, `aibomComposer`). Functional options follow the suffix-`Provider` convention (`WithPickleAnalyzerProvider`, `WithONNXValidatorProvider`, `WithSafetensorsValidatorProvider`, `WithModelCardCheckerProvider`, `WithSignatureVerifierProvider`, `WithAIBOMComposer`) — the suffix avoids colliding with `providers.WithPickleAnalyzer` (the composer-level option) at call sites that import both packages. `InitProviders` lazy-creates each sub-provider then wires them into the default composer (skipping when an override has supplied either the composer OR individual sub-providers).
- **`app.AppInterface`** — extended with `GetPickleAnalyzer`, `GetONNXValidator`, `GetSafetensorsValidator`, `GetModelCardChecker`, `GetSignatureVerifier`, `GetAIBOMComposer` so the existing compile-time guard catches any future drift.
- **`config.Config`** — new `AIBOM` section with `MaxPickleBytes`, `TrustedIssuers []string`, `AdditionalTrustedIssuers []string`. Empty values flow through as no-ops, preserving backwards-compatible defaults.
- **`providers/pickle.go`** — `NewPickleAnalyzer` now accepts variadic `PickleAnalyzerOption` and `WithPickleMaxFileBytes(int64)` overrides the outer-file size cap. Values exceeding the 2 GiB hard ceiling are clamped down to keep DoS guarantees intact. `analyzePickleFile` signature picked up an explicit `maxBytes int64` parameter; non-positive values fall back to the package-level `maxFileBytes` constant. Internal-only callers (`AnalyzeFile`, `AnalyzeDirectory`) thread the configured cap through.
- **`cmd/main.go`** — eight new flags on `scanCmd`:
  - `--skip-pickle`, `--skip-onnx`, `--skip-safetensors`, `--skip-modelcard`, `--skip-signature` — bool gates that drop findings produced by the matching sub-provider after the composer returns.
  - `--max-pickle-size <bytes>` — overrides the pickle disassembler's outer-file size cap.
  - `--trusted-issuers <csv>` — REPLACES the default OIDC issuer allowlist used by `SignatureVerifier`. Wraps `providers.WithTrustedIssuers`.
  - `--additional-trusted-issuers <csv>` — MERGES the supplied issuers into the default list. Wraps `providers.WithAdditionalTrustedIssuers`.
  - New `splitAndTrimCSV` helper trims whitespace and drops empty entries so users can paste a list directly.

### Tests
- **`engines/scanner_test.go`** — replaced the obsolete `TestScanner_Scan_RejectsModelArtifactKind` with five new test groups:
  - `TestScanner_Scan_ModelArtifactKind_DispatchesToComposer` — verifies single-file (Args[0] used as target), directory (Path used), and Args-empty fallback paths.
  - `TestScanner_Scan_ModelArtifact_NoMCPSidePipeline` — pins that SAST, dep-audit, hook-analyzer, and MCPClient.Connect are NEVER called for model targets.
  - `TestScanner_Scan_ModelArtifact_NoComposer_Errors` — verifies the nil-composer path returns a descriptive error instead of NPE.
  - `TestScanner_Scan_ModelArtifact_SkipFlags` — table test (7 cases) covering each skip flag independently plus the "skip everything" case. Each case wires a `MockAIBOMComposer` returning all five rule families and asserts the expected subset survives filtering.
  - `TestScanner_Scan_ModelDirectory_HFTarget` — simulates the HF resolver's output (Kind=KindModelDirectory + cache directory Path) and verifies dispatch works the same as a local directory scan.
  - `TestScanner_Scan_ModelArtifact_SuppressionApplied` — pins that `.oxvaultignore` runs for AIBOM scans the same way it runs for MCP scans (regression guard on the suppression contract).
- **`app/app_test.go`** — three new tests:
  - `TestInitProviders_WiresAIBOMSubProviders` — Initialize wires every getter non-nil.
  - `TestInitProviders_AIBOMOverridesNotReplaced` — functional options are not overwritten by InitProviders (lazy init contract).
  - `TestInitProviders_DefaultComposerUsesWiredSubProviders` — the default composer path consumes the wired sub-providers (sub-providers must be created BEFORE the composer in InitProviders ordering).
- All 8 existing scanner test helpers updated for the new `NewScanner` signature; `newTestScannerWithComposer` added so AIBOM-side tests don't need to wire the full mock surface manually.

### Key design decisions
- **Skip-flag filtering at the engine layer, not the composer:** the composer's contract stays "scan everything that's there"; the engine drops what the user asked to skip. This is identical to how `SkipSAST` and `SkipManifest` work for MCP scans, avoids re-constructing the composer per scan, and keeps `aibom_composer.go` untouched. Filtering is by rule-prefix (`aibom-pickle-*` etc.) so adding a new sub-provider only requires adding one prefix to `filterAIBOMFindings`.
- **Single-file vs directory target selection:** the resolver places the absolute artifact filename in `pkg.Args[0]` for single-file targets and leaves `pkg.Path` pointing at the parent directory. The engine prefers `Args[0]` when present so the composer dispatches to ONE sub-provider rather than walking the parent directory (which would surface unrelated findings). Falls back to `Path` when `Args` is empty for robustness.
- **Suppression dir for AIBOM scans uses pkg.Path (parent directory):** model authors can ship `.oxvaultignore` next to their weights without touching unrelated MCP server config. Same `Suppressor.LoadIgnoreFile + Filter` flow as MCP scans — no duplicate code path.
- **Functional-option naming uses the `Provider` suffix to avoid package shadowing:** `WithPickleAnalyzer` already exists in `providers/aibom_composer.go` as a composer-level option. The app-container option is `WithPickleAnalyzerProvider` so callers (especially tests) that import both packages don't have to use ugly aliasing.
- **`max-pickle-size` clamps down, never up:** values above the 2 GiB ceiling are silently clamped to the default. Allowing a wider cap would mean the disassembler would accept files larger than what the DoS guards are tested against — failure mode here is "scan stops early on huge file", which is the safer of the two.
- **`--trusted-issuers` REPLACES, `--additional-trusted-issuers` MERGES:** matches the `providers.WithTrustedIssuers` / `WithAdditionalTrustedIssuers` semantics that landed in Day 7. `--trusted-issuers` is the "I know exactly which issuers I want" flag; `--additional-trusted-issuers` is the "extend the defaults" flag. The CLI help text calls out the difference explicitly so users picking the wrong one is recoverable.
- **`AIBOMComposer` is optional in `NewScanner`:** wiring an AIBOM composer is mandatory for production (`app.InitEngines` always supplies one), but the parameter accepts nil for unit tests that only exercise the MCP-server flow. A nil composer hitting a model-artifact target returns a descriptive error rather than panicking — defence against accidental nil derefs in tests that build the engine directly.

### Files
- `engines/scanner.go` (Day 9 dispatch + ScanOptions extension + filterAIBOMFindings helper)
- `engines/scanner_test.go` (six new test groups, table tests for skip flags)
- `app/app.go` (six AIBOM fields, six functional options, six getters, AIBOM section in InitProviders, composer passed to NewScanner)
- `app/app_test.go` (three new app wiring tests)
- `config/config.go` (AIBOMOptions struct: MaxPickleBytes, TrustedIssuers, AdditionalTrustedIssuers)
- `providers/pickle.go` (PickleAnalyzerOption + WithPickleMaxFileBytes; analyzePickleFile signature)
- `cmd/main.go` (eight new scan flags: --skip-pickle, --skip-onnx, --skip-safetensors, --skip-modelcard, --skip-signature, --max-pickle-size, --trusted-issuers, --additional-trusted-issuers; splitAndTrimCSV helper)
- `DEVLOG.md` (this entry)

### Quality gates
- `make build` — clean
- `make test` — all packages pass (672 PASS subtests)
- `make lint` — 0 issues
- Manual end-to-end smoke:
  - `oxvault scan ./testdata/aibom/pickle/malicious/os_system.pkl` — emits `aibom-pickle-os-system` CRITICAL plus suppression-deferred signature INFO
  - `oxvault scan ./testdata/aibom/pickle/malicious/ --skip-pickle` — drops all `aibom-pickle-*` findings, surfaces `aibom-signature-missing` per artifact
  - `oxvault scan ./testdata/aibom/pickle/malicious/ --skip-pickle --skip-signature` — only `aibom-modelcard-missing` survives

---

## Day 8 — Hugging Face resolver — 2026-04-28

Branch: `feat/aibom-day8-hf-resolver`

### What shipped
- `providers/hf_resolver.go` — full HF resolver implementation. `oxvault scan hf:org/model[@revision]` now downloads relevant files to a per-(org, model, rev) cache directory and returns a `ResolvedPackage` with `Kind=KindModelDirectory` so the AIBOM composer can scan it like any other model dir.
- `parseHFTarget` — handles `hf:org/model` and `hf:org/model@revision`, validates org/model/revision shape, rejects path-traversal (`..`) in revision.
- `HFConfig` struct with functional options: `WithHFConfig`, `WithHFToken`, `WithHFRevision`, `WithHFCacheDir`, `WithHFMaxFileBytes`, `WithHFMaxCacheBytes`, `WithHFBaseURL`, `WithHFHTTPClient`. Tests inject an `httptest.Server` via `WithHFBaseURL`.
- HTTP client: 30s timeout, 3 retries with exponential backoff on 5xx, `Retry-After`-aware on 429, clear 401/403/404 errors mentioning `HF_TOKEN`.
- Filename filtering: only security-relevant files are downloaded (`.pkl`, `.pt`, `.pth`, `.bin`, `.ckpt`, `.onnx`, `.safetensors`, `.md`, `.sigstore`, `.sig`, plus exact basenames `model_signing.json`, `manifest.json`, `config.json`, `readme.md`, `model_card.md`, `model_card.yaml`, `.modelcard.yaml`).
- Per-file size cap (default 4 GiB) and total-cache size cap (default 16 GiB). Cache hit shortcut via HEAD size check — no re-download when local file size matches remote.
- Atomic temp+rename writes so a partial download never lands in cache.
- `config/config.go`: new `HF` section with env-var defaults (`HF_TOKEN`).
- `cmd/main.go`: `--hf-token`, `--hf-revision`, `--hf-cache-dir`, `--hf-max-file-bytes`, `--hf-max-cache-bytes` flags on `scanCmd`.
- `app/app.go`: `InitProviders` constructs the resolver via `NewResolverWithOptions(...)` with `HFConfig` flowed from `a.Config.HF`.

### Tests
- `parseHFTarget` table tests cover all parse paths.
- `httptest.Server` integration tests: success path, cache hit, 401 (HF_TOKEN hint), 404, 5xx retry-and-succeed. No real HF calls.

### Quality gates
- `make build` — clean
- `make test` — all 4 packages pass
- `make lint` — 0 issues

---

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
