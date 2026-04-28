# Changelog

## v0.4.0 — AIBOM (AI Bill of Materials) — 2026-04-28

Extends Oxvault from MCP-only to also cover **ML model artifacts**. Same scanner engine, four new file formats, ~38 new detection rules.

### Added — model artifact scanning

| Format | Provider | Rules |
|---|---|---|
| Pickle (`.pkl`, `.pt`, `.pth`) | `providers/pickle.go` — opcode disassembler, no execution | 11 (`aibom-pickle-os-system` CRIT through `-allowlisted` INFO) |
| Safetensors (`.safetensors`) | `providers/safetensors.go` — header + offset + metadata validation | 8 (`-header-overflow` CRIT through `-clean` INFO) |
| ONNX (`.onnx`) | `providers/onnx.go` — protobuf wire walker, no codegen | 7 (`-malformed-protobuf` HIGH through `-clean` INFO) |
| Model card (`README.md`, `model_card.yaml`) | `providers/modelcard.go` — yaml.v3 frontmatter + RuleMatcher reuse | 9 (`-suspicious-instructions` HIGH through `-clean` INFO) |
| Signature (`model_signing.json`, `.sigstore`, `.sig`) | `providers/signature.go` — OpenSSF Model Signing manifest, hash-only | 7 (`-hash-mismatch` CRIT, `-untrusted-issuer` HIGH, etc.) |

### Added — `oxvault scan hf:org/model[@revision]`

`providers/hf_resolver.go` materialises HF repos to `~/.cache/oxvault/hf/{org}/{model}/{rev}/` and dispatches to the AIBOM composer.

- HF API v1 manifest, filename allowlist (security-relevant files only)
- Per-file 4 GiB cap, total cache 16 GiB cap
- HEAD-based cache-hit short-circuit, atomic temp+rename writes
- `os.Root`-scoped I/O (Go 1.25 — symlink-safe)
- HTTP: 30s timeout, exp backoff on 5xx, Retry-After honored
- `CheckRedirect` strips Authorization on cross-host, bounds redirects
- HF token redacted via `slog.LogValuer`

### Added — CLI flags

```
--skip-pickle               skip pickle disassembler
--skip-onnx                 skip ONNX validator
--skip-safetensors          skip safetensors validator
--skip-modelcard            skip model card checker
--skip-signature            skip signature verifier
--max-pickle-size           per-file cap (clamps down to 2 GiB ceiling)
--trusted-issuers           CSV — REPLACES default OIDC issuer allowlist
--additional-trusted-issuers CSV — MERGES with defaults

--hf-token                  HF auth token (env: HF_TOKEN)
--hf-revision               default: main
--hf-cache-dir              default: ~/.cache/oxvault/hf
--hf-max-file-bytes         default: 4 GiB
--hf-max-cache-bytes        default: 16 GiB
```

### Added — dependencies

- `gopkg.in/yaml.v3 v3.0.1` — model card frontmatter parsing

### Architecture

- `providers/aibom_composer.go` — dispatches by `ArtifactFormat`, drives missing-card and missing-signature aggregation across directory walks
- `engines/scanner.go` — branches on `pkg.Kind` (KindMCPServer / KindModelArtifact / KindModelDirectory) and routes accordingly
- Same `Finding` type, same `Reporter`, same `.oxvaultignore` suppression. Existing MCP code paths unchanged.

### Trust posture (read carefully)

v0.4 ships **hash-only** signature verification. The `aibom-signature-hash-match` rule fires when manifest SHA-256 matches the artifact AND the issuer is in the trusted list — but the issuer claim is **self-declared**. There is no cryptographic proof of who signed. A `aibom-signature-clean` rule is **reserved for v0.4.1**, when full Sigstore Rekor/Fulcio verification lands.

Sigstore bundles (`.sigstore`) and loose signatures (`.sig`) get presence + spec-shape checks but **no cryptographic verification** in v0.4 — they emit `aibom-signature-presence-deferred`.

### Breaking changes

None. All v0.3 MCP scans behave identically.

### Test coverage

- ~672 tests across `app`, `config`, `engines`, `providers` (was ~480 in v0.3.3)
- 25+ AIBOM-specific binary fixtures under `testdata/aibom/`
- All malicious fixtures produce expected rule IDs in regression tests
- `httptest.Server` integration coverage for HF resolver (no real HF calls in tests)
- `make scan-demo` exercises every detector end-to-end

### Deferred to v0.4.1

- Full Sigstore Rekor/Fulcio chain verification (currently hash-only)
- Cross-resolve cache cap accounting (currently per-resolve)
- Signal-aware `context.Context` plumbing through `Resolver.Resolve`

### Deferred to v0.5

- RAG corpus scanning (same poisoning engine applied to indexed documents)

---

## v0.3.3 — 2026-04-04

See git log: scanner security hardening, CORS, role middleware, body size limits, env-var configuration.
