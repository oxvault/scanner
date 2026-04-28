# Vulnerable Model Artifacts — AIBOM v0.4 Demos

These are intentionally bad ML model artifacts that demonstrate Oxvault's AIBOM (AI Bill of Materials) detection capabilities. Run `oxvault scan` against any of them to see the scanner in action.

**All fixtures here are inert.** They detect attack patterns but don't actually execute anything malicious. The pickle files reference dangerous globals via opcodes; loading them in Python *would* execute, but Oxvault never calls `pickle.load`.

## Demos

| Directory | Detection | Severity |
|---|---|---|
| `pickle-rce/` | `os.system` referenced via REDUCE opcode (CWE-502) | CRITICAL |
| `safetensors-overflow/` | Header length larger than file size (CWE-1284) | CRITICAL |
| `onnx-malformed/` | Garbage bytes that fail protobuf parse (CWE-1284) | HIGH |
| `modelcard-poisoned/` | README.md carrying prompt-injection patterns (CWE-1039) | HIGH |
| `unsigned/` | Clean torch state_dict, no signature manifest | WARNING |

## Run them

```bash
# Single artifact
oxvault scan ./examples/vulnerable-models/pickle-rce/weights.pkl

# Whole directory
oxvault scan ./examples/vulnerable-models/

# Or use the make target
make scan-demo
```

## Why each one matters

### pickle-rce
PyTorch ships models as Python pickles. `torch.load("weights.pkl")` is a thin wrapper around `pickle.load`. Pickle has a `REDUCE` opcode that says "call this function with these arguments" — `os.system` is a function. Done. This is the #1 ML supply-chain attack.

### safetensors-overflow
Hugging Face pushes safetensors as the "safe" alternative to pickle. Safer (no opcodes), but still has parser-confusion attacks. A malicious header length larger than the file misleads downstream loaders.

### onnx-malformed
ONNX is protobuf-encoded. Garbage bytes that fail to parse are either corruption or attack. Either way, don't load.

### modelcard-poisoned
Model cards (README.md, model_card.yaml) ship alongside HF models. Hidden Unicode tags, BiDi reversal, and `<IMPORTANT>` blocks can poison agents that read the card.

This demo includes a clean `weights.pkl` next to the poisoned `README.md` — the scanner treats a directory as "model" only when at least one model artifact lives alongside the card. Bare card-only dirs route as MCP and skip AIBOM checks.

### unsigned
Clean model, but no signature manifest. Lower severity than active attacks, but provenance gaps matter for compliance (EU AI Act, NSA AI Supply Chain).
