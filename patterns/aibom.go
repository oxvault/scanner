package patterns

import "regexp"

// AIBOM dangerous-globals catalog.
//
// These maps key on the fully-qualified Python name pushed onto the pickle
// stack via the GLOBAL or STACK_GLOBAL opcode (e.g. "os.system"). They feed
// the pickle disassembler in providers/pickle.go — pure data only.
//
// Tier semantics:
//
//   - Critical : direct shell / code-execution primitives. Any reference is
//     a high-confidence finding regardless of whether REDUCE is present,
//     because a benign pickle never needs to import them.
//   - High     : network egress primitives. Frequently abused for exfil.
//   - Medium   : destructive filesystem primitives. Allowed in some legitimate
//     model loaders but warrant attention.
//
// AllowedMLGlobals is the suppress-to-INFO allowlist of well-known torch and
// numpy reconstruction helpers that are safe in practice. Any GLOBAL ref
// matching this set short-circuits to INFO severity.

// DangerousGlobalsCritical maps qualified-name → human-readable rationale for
// callables that grant arbitrary shell or code execution on load.
var DangerousGlobalsCritical = map[string]string{
	// Shell execution
	"os.system":                "spawns shell command",
	"os.popen":                 "spawns shell command via popen",
	"posix.system":             "spawns shell command (posix alias)",
	"posix.popen":              "spawns shell command via popen (posix alias)",
	"nt.system":                "spawns shell command (nt alias)",
	"commands.getoutput":       "legacy commands.getoutput shell exec",
	"commands.getstatusoutput": "legacy commands.getstatusoutput shell exec",
	"pty.spawn":                "spawns interactive shell via pty",

	// subprocess family
	"subprocess.Popen":           "subprocess process creation",
	"subprocess.call":            "subprocess command execution",
	"subprocess.run":             "subprocess command execution",
	"subprocess.check_call":      "subprocess command execution",
	"subprocess.check_output":    "subprocess command execution",
	"subprocess.getoutput":       "subprocess command execution",
	"subprocess.getstatusoutput": "subprocess command execution",

	// builtins eval/exec/compile/import family
	"builtins.eval":          "dynamic code evaluation",
	"builtins.exec":          "dynamic code execution",
	"builtins.compile":       "dynamic code compilation",
	"builtins.__import__":    "dynamic module import",
	"__builtin__.eval":       "dynamic code evaluation (py2 alias)",
	"__builtin__.exec":       "dynamic code execution (py2 alias)",
	"__builtin__.compile":    "dynamic code compilation (py2 alias)",
	"__builtin__.__import__": "dynamic module import (py2 alias)",

	// importlib
	"importlib.import_module":                        "dynamic module import",
	"importlib.__import__":                           "dynamic module import",
	"importlib._bootstrap._call_with_frames_removed": "dynamic module import (internal)",

	// runpy — runs Python source from a file or module
	"runpy._run_code":           "runs arbitrary Python source",
	"runpy.run_module":          "runs arbitrary Python module",
	"runpy.run_path":            "runs arbitrary Python source from path",
	"runpy._run_module_as_main": "runs arbitrary Python module as __main__",
}

// DangerousGlobalsHigh maps qualified-name → rationale for network-egress
// callables. Frequently used by malicious pickles to exfiltrate secrets.
var DangerousGlobalsHigh = map[string]string{
	// socket
	"socket.socket":            "raw socket creation",
	"socket.create_connection": "outbound TCP connection",
	"socket.gethostbyname":     "DNS resolution",

	// urllib (py3)
	"urllib.request.urlopen":     "HTTP fetch",
	"urllib.request.Request":     "HTTP request construction",
	"urllib.request.urlretrieve": "HTTP file download",

	// urllib2 (py2)
	"urllib2.urlopen": "HTTP fetch (py2)",
	"urllib2.Request": "HTTP request (py2)",

	// requests
	"requests.get":     "HTTP GET",
	"requests.post":    "HTTP POST",
	"requests.put":     "HTTP PUT",
	"requests.delete":  "HTTP DELETE",
	"requests.patch":   "HTTP PATCH",
	"requests.head":    "HTTP HEAD",
	"requests.request": "arbitrary HTTP request",
	"requests.Session": "HTTP session creation",

	// httpx
	"httpx.get":     "HTTP GET (httpx)",
	"httpx.post":    "HTTP POST (httpx)",
	"httpx.put":     "HTTP PUT (httpx)",
	"httpx.delete":  "HTTP DELETE (httpx)",
	"httpx.patch":   "HTTP PATCH (httpx)",
	"httpx.head":    "HTTP HEAD (httpx)",
	"httpx.request": "arbitrary HTTP request (httpx)",
	"httpx.Client":  "HTTP client (httpx)",

	// http.client
	"http.client.HTTPConnection":  "raw HTTP connection",
	"http.client.HTTPSConnection": "raw HTTPS connection",

	// ftp / telnet / smtp / smb
	"ftplib.FTP":       "FTP connection",
	"ftplib.FTP_TLS":   "FTPS connection",
	"telnetlib.Telnet": "Telnet connection",
	"smtplib.SMTP":     "SMTP connection",
	"smtplib.SMTP_SSL": "SMTPS connection",

	// websockets / aiohttp clients
	"aiohttp.ClientSession": "async HTTP session",
	"aiohttp.request":       "async HTTP request",
	"websocket.WebSocket":   "WebSocket connection",
	"websockets.connect":    "async WebSocket connection",
}

// DangerousGlobalsMedium maps qualified-name → rationale for destructive
// filesystem callables. Some legitimate loaders touch these, so confidence
// is downgraded relative to the Critical tier.
var DangerousGlobalsMedium = map[string]string{
	// shutil
	"shutil.copy":     "filesystem copy",
	"shutil.copy2":    "filesystem copy (with metadata)",
	"shutil.copytree": "recursive filesystem copy",
	"shutil.move":     "filesystem move",
	"shutil.rmtree":   "recursive filesystem deletion",

	// os.* destructive
	"os.remove":     "file deletion",
	"os.unlink":     "file deletion (alias)",
	"os.rmdir":      "empty-dir deletion",
	"os.removedirs": "recursive empty-dir deletion",
	"os.rename":     "file rename",
	"os.replace":    "file replace",
	"os.truncate":   "file truncate",
	"os.chmod":      "file permission change",
	"os.chown":      "file ownership change",
	"os.symlink":    "symlink creation",
	"os.link":       "hardlink creation",
	"posix.unlink":  "file deletion (posix alias)",

	// pathlib write paths
	"pathlib.Path.write_text":  "pathlib file write (text)",
	"pathlib.Path.write_bytes": "pathlib file write (bytes)",
	"pathlib.Path.unlink":      "pathlib file deletion",
	"pathlib.Path.rmdir":       "pathlib empty-dir deletion",
	"pathlib.Path.mkdir":       "pathlib directory creation",
	"pathlib.Path.touch":       "pathlib file creation",
	"pathlib.Path.rename":      "pathlib file rename",
	"pathlib.Path.replace":     "pathlib file replace",
	"pathlib.Path.chmod":       "pathlib permission change",
	"pathlib.Path.symlink_to":  "pathlib symlink creation",
}

// AllowedMLGlobals is the allowlist of well-known ML-framework helpers that
// are safe to see during pickle deserialization. Findings that ONLY contain
// allowlisted globals are surfaced at INFO severity.
//
// Keys ending in ".*" are treated as prefixes by the disassembler.
var AllowedMLGlobals = map[string]bool{
	// torch reconstruction helpers
	"torch._utils._rebuild_tensor_v2":                true,
	"torch._utils._rebuild_tensor_v3":                true,
	"torch._utils._rebuild_parameter":                true,
	"torch._utils._rebuild_parameter_with_state":     true,
	"torch._utils._rebuild_qtensor":                  true,
	"torch._utils._rebuild_sparse_tensor":            true,
	"torch._utils._rebuild_meta_tensor_no_storage":   true,
	"torch._utils._rebuild_xla_tensor":               true,
	"torch._utils._rebuild_device_tensor_from_numpy": true,
	"torch._utils._rebuild_wrapper_subclass":         true,

	// torch storage types
	"torch.FloatStorage":             true,
	"torch.DoubleStorage":            true,
	"torch.HalfStorage":              true,
	"torch.LongStorage":              true,
	"torch.IntStorage":               true,
	"torch.ShortStorage":             true,
	"torch.CharStorage":              true,
	"torch.ByteStorage":              true,
	"torch.BoolStorage":              true,
	"torch.BFloat16Storage":          true,
	"torch.ComplexFloatStorage":      true,
	"torch.ComplexDoubleStorage":     true,
	"torch.QUInt8Storage":            true,
	"torch.QInt8Storage":             true,
	"torch.QInt32Storage":            true,
	"torch._C._TensorBase":           true,
	"torch.Tensor":                   true,
	"torch.Size":                     true,
	"torch.device":                   true,
	"torch.dtype":                    true,
	"torch.Generator":                true,
	"torch.storage._load_from_bytes": true,
	"torch.storage._StorageBase":     true,

	// numpy reconstruction helpers
	"numpy.core.multiarray._reconstruct":  true,
	"numpy.core.multiarray.scalar":        true,
	"numpy.dtype":                         true,
	"numpy.ndarray":                       true,
	"numpy.core.numeric._frombuffer":      true,
	"numpy._core.multiarray._reconstruct": true,
	"numpy._core.multiarray.scalar":       true,

	// stdlib containers
	"collections.OrderedDict": true,
	"collections.defaultdict": true,
	"collections.Counter":     true,
	"collections.deque":       true,

	// codecs (legitimate within pickled strings)
	"_codecs.encode": true,
	"_codecs.decode": true,

	// builtins constructors used by pickled native types
	"builtins.dict":      true,
	"builtins.list":      true,
	"builtins.tuple":     true,
	"builtins.set":       true,
	"builtins.frozenset": true,
	"builtins.str":       true,
	"builtins.bytes":     true,
	"builtins.bytearray": true,
	"builtins.int":       true,
	"builtins.float":     true,
	"builtins.bool":      true,
	"builtins.complex":   true,
	"builtins.range":     true,
	"builtins.slice":     true,
	"builtins.object":    true,
	"builtins.type":      true,
}

// AllowedMLGlobalPrefixes are package prefixes whose members are all
// considered safe ML reconstruction helpers (e.g. all of torch.nn.modules.*).
//
// Each entry is a fully-qualified prefix WITHOUT trailing ".*".
var AllowedMLGlobalPrefixes = []string{
	"torch.nn.modules.",
	"torch.nn.parameter.",
	"torch.nn.functional.",
	"torch.optim.",
	"torch.distributions.",
	"torch.cuda.amp.",
	"torch.utils.checkpoint.",
	"torchvision.models.",
	"torchvision.transforms.",
	"transformers.models.",
}

// IsAllowedMLGlobal returns true if the qualified name is an allowlisted ML
// reconstruction helper. Both exact matches and prefix matches are honoured.
func IsAllowedMLGlobal(qualified string) bool {
	if AllowedMLGlobals[qualified] {
		return true
	}
	for _, prefix := range AllowedMLGlobalPrefixes {
		if len(qualified) >= len(prefix) && qualified[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

// ── safetensors validator data ──────────────────────────────────────────────
//
// The lists below feed providers/safetensors.go. Pure data only — no
// behaviour. Keeping these in patterns/ honours the project's layering rule:
// providers/ depends on patterns/, never the reverse.

// ValidSafetensorDtypes is the set of dtype strings recognised by the
// HuggingFace safetensors specification. Any dtype outside this set is a
// strong indicator of a hand-crafted (potentially malicious) header.
//
// Reference: https://github.com/huggingface/safetensors#format
var ValidSafetensorDtypes = map[string]bool{
	"F64":     true, // float64
	"F32":     true, // float32
	"F16":     true, // float16
	"BF16":    true, // bfloat16
	"I64":     true, // int64
	"I32":     true, // int32
	"I16":     true, // int16
	"I8":      true, // int8
	"U64":     true, // uint64 (rare but valid per spec)
	"U32":     true, // uint32
	"U16":     true, // uint16
	"U8":      true, // uint8
	"BOOL":    true, // boolean tensor
	"F8_E4M3": true, // 8-bit float (E4M3) — newer spec addition
	"F8_E5M2": true, // 8-bit float (E5M2) — newer spec addition
}

// SafetensorsShellMetacharacters is the set of shell-control characters that,
// when found inside a `__metadata__` value, suggest the metadata is being
// abused as a smuggle channel for a downstream agent's shell. Detection is
// conservative — only fires when a metacharacter is present.
var SafetensorsShellMetacharacters = []string{
	";",
	"|",
	"&&",
	"||",
	"$(",
	"`",
	">/",
	"<(",
}

// SafetensorsPickleMagicEscapes is the JSON-source form of the pickle magic
// bytes — what a malicious header looks like ON DISK before JSON decoding.
// We scan the raw header bytes for these so we catch the attack regardless
// of whether the value is valid UTF-8 once decoded.
var SafetensorsPickleMagicEscapes = []string{
	"\\u0080\\u0002", // pickle protocol 2
	"\\u0080\\u0003", // pickle protocol 3
	"\\u0080\\u0004", // pickle protocol 4
	"\\u0080\\u0005", // pickle protocol 5
}

// SafetensorsURLPrefixes are URL-scheme prefixes whose presence in metadata
// is suspicious — safetensors metadata is meant for human-readable provenance
// (training framework, license), not callbacks or remote references.
var SafetensorsURLPrefixes = []string{
	"http://",
	"https://",
	"ftp://",
	"ftps://",
	"file://",
	"javascript:",
	"data:",
}

// ── ONNX validator data ─────────────────────────────────────────────────────
//
// The lists below feed providers/onnx.go. Pure data only — no behaviour.
// Keeping these in patterns/ honours the project's layering rule:
// providers/ depends on patterns/, never the reverse.

// ONNXStandardDomains is the set of operator domains officially defined by
// the ONNX specification. Anything else is an opaque custom operator that an
// inference runtime would need a vendor-specific kernel to execute — and is
// the standard channel for smuggling unsafe behaviour into a model graph.
//
// Reference: https://github.com/onnx/onnx/blob/main/docs/Versioning.md#operator-set-domains
var ONNXStandardDomains = map[string]bool{
	"":                         true, // empty == default ai.onnx domain
	"ai.onnx":                  true,
	"ai.onnx.ml":               true,
	"ai.onnx.training":         true,
	"ai.onnx.preview.training": true,
}

// ONNXSuspiciousDomainSubstrings lists substrings whose presence inside an
// operator domain is a strong hint that the domain references arbitrary code
// (a URL, a vendor-rooted package path, or a known-bad name). The match is
// case-insensitive.
var ONNXSuspiciousDomainSubstrings = []string{
	"http://",
	"https://",
	"ftp://",
	"file://",
	"javascript:",
	"data:",
	"/", // any forward slash is unusual in legitimate ONNX domains
	"\\",
	"contrib.malicious",
}

// ONNXSuspiciousExternalDataPrefixes flags external_data location values that
// point outside the model's directory or to remote resources.
var ONNXSuspiciousExternalDataPrefixes = []string{
	"http://",
	"https://",
	"ftp://",
	"ftps://",
	"file://",
	"javascript:",
	"data:",
}

// MaxOnnxTensorElements caps the number of elements an initializer may declare
// before we flag it as oversized. Default is 256M elements (≈ 1 GiB at 4-byte
// float32). Real production models with huge embedding tables can exceed this,
// so the rule fires at WARNING — not HIGH/CRITICAL.
const MaxOnnxTensorElements uint64 = 256 * 1024 * 1024

// MaxOnnxFileBytes caps the on-disk size of an .onnx file the validator will
// read. ONNX models can be large (multi-GiB) but anything beyond 4 GiB is
// vanishingly rare in practice and any pathological producer hitting this cap
// would be smaller, so we fail closed with a malformed-protobuf finding.
const MaxOnnxFileBytes int64 = 4 * 1024 * 1024 * 1024

// ── model-card checker data ─────────────────────────────────────────────────
//
// These lists feed providers/modelcard.go. Pure data only — no behaviour.
// Keeping them in patterns/ honours the project's layering rule:
// providers/ depends on patterns/, never the reverse.

// MaxModelCardFileBytes caps the on-disk size of a model-card document the
// checker will read. Model cards are documentation — anything beyond 1 MiB is
// almost certainly not a real card, so we refuse to read it.
const MaxModelCardFileBytes int64 = 1 * 1024 * 1024

// ModelCardLicenseKeys is the set of YAML frontmatter keys that legitimately
// declare a model's license. Both US and UK spellings are accepted because
// HuggingFace's spec is silent on the spelling and producers in the wild use
// both. Match is case-insensitive (the checker lowercases before lookup).
var ModelCardLicenseKeys = map[string]bool{
	"license":  true,
	"licence":  true, // UK spelling — observed in some HF cards
	"licenses": true, // plural form occasionally used for multi-license declarations
	"licences": true,
}

// ModelCardSourceKeys is the set of YAML frontmatter keys that declare model
// provenance — base model lineage, training data references, or a parent
// model registry link. Presence of ANY of these keys (with a non-empty value)
// is sufficient to pass the no-source check.
var ModelCardSourceKeys = map[string]bool{
	"base_model":     true,
	"base_models":    true, // plural form for multi-base lineage
	"source":         true,
	"sources":        true,
	"training_data":  true,
	"datasets":       true, // HuggingFace canonical key
	"dataset":        true,
	"parent_model":   true,
	"parent_models":  true,
	"finetuned_from": true,
	"derived_from":   true,
}

// ModelCardEvalKeys is the set of YAML frontmatter keys that declare an
// evaluation or benchmark section for the model. Presence in frontmatter is
// sufficient to pass the no-eval check; presence of a body section heading
// is also sufficient (see ModelCardEvalSectionHeaders).
var ModelCardEvalKeys = map[string]bool{
	"eval":        true,
	"evaluation":  true,
	"evaluations": true,
	"benchmark":   true,
	"benchmarks":  true,
	"metrics":     true,
	"model-index": true, // HuggingFace canonical eval block
	"model_index": true,
	"results":     true,
	"performance": true,
}

// ModelCardLicenseSectionHeaders matches markdown body headings whose presence
// indicates a license declaration in the body. Levels 1-6 are accepted; the
// match is case-insensitive and ignores leading/trailing whitespace.
//
// Each pattern matches the START of a line — frontmatter has already been
// stripped before the body is scanned, so leading-line semantics are stable.
var ModelCardLicenseSectionHeaders = regexp.MustCompile(`(?im)^\s*#{1,6}\s*licen[cs]e\b`)

// ModelCardEvalSectionHeaders matches markdown body headings whose presence
// indicates an evaluation/benchmark declaration in the body.
var ModelCardEvalSectionHeaders = regexp.MustCompile(`(?im)^\s*#{1,6}\s*(evaluation|eval|benchmark|benchmarks|metrics|results|performance)\b`)

// ModelCardClaimRegex matches mentions of accuracy/F1/AUC/precision NUMBERS in
// model-card body text. The presence of a number-bearing claim WITHOUT a
// citation or eval section is suspicious — it may indicate an unsupported
// performance claim used to lure users into trusting the model.
//
// Examples that match:
//
//	"94.2% accuracy"
//	"accuracy: 0.95"
//	"F1 = 0.92"
//	"AUC of 0.99"
//	"precision: 0.87"
//	"recall=0.81"
//
// The regex is intentionally broad — false-positives downgrade to INFO
// severity, never HIGH or CRITICAL.
var ModelCardClaimRegex = regexp.MustCompile(`(?i)\b(accuracy|f1|f-1|auc|auroc|aupr|precision|recall|bleu|rouge|perplexity|mAP|top-?[15])\b[^\n]{0,40}?(?:[:=]\s*|of\s+|\s+is\s+|\s+)?(?:\d+\.?\d*\s*%|0?\.\d+|\d+\.\d+)`)

// ModelCardCitationRegex matches inline citations or external references in
// the body that satisfy the "claim has a citation" requirement. Any of:
//
//	[ref](url) markdown links
//	(arXiv:xxxx.xxxxx) academic refs
//	"see https://..."
//	"@citation"
//
// If a body contains BOTH a claim AND a matching citation pattern (or the
// body has an explicit ## Evaluation / ## Benchmarks heading), the no-eval
// check passes.
var ModelCardCitationRegex = regexp.MustCompile(`(?i)(\[[^\]]+\]\([^)]+\)|arxiv[:\.\s][\d\.]+|doi[:\s]|https?://[^\s)]+|see\s+(table|figure)\s+\d+|@[a-z][a-z0-9_-]+\b)`)

// ── signature verifier data ─────────────────────────────────────────────────
//
// These lists feed providers/signature.go. Pure data only — no behaviour.
// Keeping them in patterns/ honours the project's layering rule:
// providers/ depends on patterns/, never the reverse.
//
// Day 7 ships hash-manifest verification only — the OpenSSF Model Signing
// JSON manifest format. Full Sigstore Rekor/Fulcio verification is deferred
// to v0.4.1; for now we recognise .sigstore bundle files (presence + JSON
// shape) and loose .sig files (presence only) without verifying their
// cryptographic provenance.

// MaxSignatureManifestBytes caps the on-disk size of a signature manifest
// (`model_signing.json`, `manifest.json`) and a sigstore bundle (`.sigstore`)
// the verifier will read. Real-world manifests are tiny (a few KiB at most);
// anything beyond 256 KiB is either generated noise or an attempt to drown
// the JSON parser in irrelevant bytes.
const MaxSignatureManifestBytes int64 = 256 * 1024

// DefaultTrustedSignatureIssuers is the seed list of OIDC identity issuers
// the verifier accepts when WithTrustedIssuers is not supplied. These are the
// issuers commonly seen in OpenSSF Model Signing manifests and Sigstore
// keyless workflows.
//
// Users can extend or replace this list via WithTrustedIssuers — the list
// here is intentionally narrow to avoid accidentally trusting issuers a user
// did not vet.
var DefaultTrustedSignatureIssuers = []string{
	"https://accounts.google.com",
	"https://github.com/login/oauth",
	"https://token.actions.githubusercontent.com",
	"https://oauth2.sigstore.dev/auth",
	"https://login.microsoftonline.com",
	"https://gitlab.com",
}

// SignatureManifestNames lists the basenames the verifier recognises as
// OpenSSF Model Signing manifests. The match is case-insensitive (the
// verifier lowercases before lookup).
var SignatureManifestNames = map[string]bool{
	"model_signing.json": true,
	"manifest.json":      true,
}

// SigstoreBundleExt is the file extension for a Sigstore bundle (.sigstore).
// Day 7 only checks presence + JSON shape — Rekor/Fulcio verification is
// deferred to v0.4.1.
const SigstoreBundleExt = ".sigstore"

// LooseSignatureExt is the file extension for a loose detached signature
// (.sig). Day 7 only checks presence — the signature payload itself is not
// inspected.
const LooseSignatureExt = ".sig"

// SignatureModelArtifactExtensions is the set of file extensions the
// signature verifier treats as "model artifacts" for the purposes of looking
// for paired signature files. This intentionally mirrors the artifact
// formats handled by the AIBOM pickle / onnx / safetensors providers.
var SignatureModelArtifactExtensions = map[string]bool{
	".pkl":         true,
	".pickle":      true,
	".pt":          true,
	".pth":         true,
	".bin":         true,
	".ckpt":        true,
	".onnx":        true,
	".safetensors": true,
}
