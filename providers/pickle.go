package providers

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/oxvault/scanner/patterns"
)

// Pickle disassembler — pure-Go opcode walker.
//
// The implementation reads a pickle byte-stream and tracks the operand stack
// AT THE OPCODE LEVEL. It NEVER executes any callable referenced by GLOBAL,
// STACK_GLOBAL, REDUCE, INST, OBJ, NEWOBJ, NEWOBJ_EX, or BUILD. The goal is to
// detect malicious payloads BEFORE the ML model is ever loaded by Python.
//
// Stream limits guard against DoS:
//
//   - maxOpcodes caps the total number of opcodes processed per pickle stream.
//   - maxStackSize caps the operand-stack depth.
//   - maxRecursionDepth caps how deep we descend into nested ZIP-wrapped pickles.
//   - maxByteArg caps the size of length-prefixed payloads (skipped, not loaded).
//
// All limits are intentionally generous so that real torch state_dicts (which
// can have hundreds of thousands of opcodes) parse successfully.

const (
	maxOpcodes        = 1_000_000
	maxStackSize      = 200_000
	maxRecursionDepth = 4
	maxByteArg        = 1 << 30 // 1 GiB cap on any single length-prefixed arg
	maxFileBytes      = 1 << 31 // 2 GiB cap on the outer pickle file read
	maxInnerPickles   = 16      // Max pickle entries we descend into per ZIP archive
)

// pickleAnalyzer is the production PickleAnalyzer. It is stateless apart
// from the configured outer-file size cap (maxFileBytes when zero) — every
// call to AnalyzeFile / AnalyzeDirectory creates a fresh disassembler.
type pickleAnalyzer struct {
	// maxBytes overrides the default outer-file size cap. Zero falls through
	// to maxFileBytes (2 GiB), which is also the safety upper bound — a
	// caller asking for a larger cap is silently clamped back to the
	// default to keep DoS guarantees intact.
	maxBytes int64
}

// PickleAnalyzerOption configures the analyzer. Functional-option style
// matches the rest of the AIBOM module (composer, signature verifier).
type PickleAnalyzerOption func(*pickleAnalyzer)

// WithPickleMaxFileBytes overrides the outer-file size cap (default 2 GiB).
// Values <= 0 leave the default in place; values exceeding the 2 GiB
// hard ceiling are clamped down so the DoS guard cannot be widened beyond
// what the disassembler is tested against.
func WithPickleMaxFileBytes(n int64) PickleAnalyzerOption {
	return func(p *pickleAnalyzer) {
		if n <= 0 {
			return
		}
		if n > int64(maxFileBytes) {
			n = int64(maxFileBytes)
		}
		p.maxBytes = n
	}
}

// NewPickleAnalyzer returns a PickleAnalyzer.
func NewPickleAnalyzer(opts ...PickleAnalyzerOption) PickleAnalyzer {
	p := &pickleAnalyzer{}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// effectiveMaxBytes returns the configured cap, falling back to the package
// default when the analyzer was constructed without a custom value.
func (p *pickleAnalyzer) effectiveMaxBytes() int64 {
	if p.maxBytes <= 0 {
		return int64(maxFileBytes)
	}
	return p.maxBytes
}

// AnalyzeFile reads the file at path, disassembles its pickle opcode stream,
// and returns one Finding per dangerous (or allowlisted) GLOBAL reference.
//
// Files that look like a ZIP archive (PyTorch save format) are unwrapped
// transparently and the inner data.pkl is analysed instead.
func (p *pickleAnalyzer) AnalyzeFile(path string) []Finding {
	return analyzePickleFile(path, 0, p.effectiveMaxBytes())
}

// AnalyzeDirectory walks dir and analyses every pickle/torch file found.
//
// In production the AIBOMComposer owns directory walking, so this method
// is rarely called — but keeping it functional satisfies the interface and
// makes the analyzer usable standalone.
func (p *pickleAnalyzer) AnalyzeDirectory(dir string) []Finding {
	var findings []Finding
	max := p.effectiveMaxBytes()
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if info.IsDir() {
			if IsExcludedDir(filepath.Base(path)) {
				return filepath.SkipDir
			}
			return nil
		}
		if DetectArtifactFormat(path) != FormatPickle {
			return nil
		}
		findings = append(findings, analyzePickleFile(path, 0, max)...)
		return nil
	})
	return findings
}

// analyzePickleFile is the actual entry point. It opens the file, applies the
// outer-file size cap via io.LimitReader, and then dispatches to analyzePickleBytes
// which enforces the recursion-depth guard for every code path (file → zip →
// inner pickle).
//
// The effective cap is supplied by the caller so PickleAnalyzer instances
// constructed with WithPickleMaxFileBytes can apply a tighter limit. A
// zero or negative max falls back to the package default.
func analyzePickleFile(path string, depth int, maxBytes int64) []Finding {
	if maxBytes <= 0 {
		maxBytes = int64(maxFileBytes)
	}
	f, err := os.Open(path) //nolint:gosec // path is filesystem-walk scoped to the scan target.
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	// Bounded read: peek one extra byte so we can detect oversize files.
	limited := io.LimitReader(f, maxBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil
	}

	if int64(len(data)) > maxBytes {
		return []Finding{{
			Rule:            "aibom-pickle-truncated",
			Severity:        SeverityWarning,
			Confidence:      ConfidenceHigh,
			ConfidenceLabel: ConfidenceHigh.String(),
			File:            path,
			Message: fmt.Sprintf(
				"pickle file exceeds %d-byte safety cap — disassembly skipped",
				maxBytes),
			CWE: "CWE-1287",
		}}
	}

	return analyzePickleBytes(path, data, depth)
}

// analyzePickleBytes inspects a byte slice. It first enforces maxRecursionDepth so
// that ZIP-wrapped pickles cannot bypass the guard via repeated zip → pickle
// recursion, then tests the ZIP magic header (PyTorch zip-wrapped pickles); if
// matched, it descends into the archive and analyses the embedded data.pkl
// entry.
//
// A defer recover() wraps every ZIP path because Go's archive/zip stdlib has
// historically panicked on malformed inputs — defence in depth.
func analyzePickleBytes(path string, data []byte, depth int) (findings []Finding) {
	if depth > maxRecursionDepth {
		return []Finding{{
			Rule:            "aibom-pickle-truncated",
			Severity:        SeverityWarning,
			Confidence:      ConfidenceHigh,
			ConfidenceLabel: ConfidenceHigh.String(),
			File:            path,
			Message: fmt.Sprintf(
				"pickle recursion depth %d exceeded — refusing to descend further",
				maxRecursionDepth),
			CWE: "CWE-1287",
		}}
	}

	defer func() {
		// Defensive: a malformed ZIP must NEVER take down the scanner.
		if r := recover(); r != nil {
			findings = append(findings, Finding{
				Rule:            "aibom-pickle-truncated",
				Severity:        SeverityWarning,
				Confidence:      ConfidenceHigh,
				ConfidenceLabel: ConfidenceHigh.String(),
				File:            path,
				Message:         fmt.Sprintf("panic during ZIP/pickle analysis: %v", r),
				CWE:             "CWE-1287",
			})
		}
	}()

	if isZipArchive(data) {
		return analyzePickleZip(path, data, depth)
	}

	d := newDisassembler(path, data)
	d.run()
	return d.emit()
}

// isZipArchive reports whether data starts with the local-file-header magic
// `PK\x03\x04`. PyTorch saves models as ZIP archives by default since 1.6.
func isZipArchive(data []byte) bool {
	return len(data) >= 4 && data[0] == 'P' && data[1] == 'K' && data[2] == 0x03 && data[3] == 0x04
}

// analyzePickleZip extracts the inner pickle entry from a PyTorch zip-wrapped file
// and recursively analyses it. Common entry names: "archive/data.pkl",
// "data.pkl", or any "*/data.pkl" inside the archive.
func analyzePickleZip(path string, data []byte, depth int) []Finding {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return []Finding{{
			Rule:            "aibom-pickle-truncated",
			Severity:        SeverityWarning,
			Confidence:      ConfidenceHigh,
			ConfidenceLabel: ConfidenceHigh.String(),
			File:            path,
			Message:         "PyTorch ZIP archive could not be parsed: " + err.Error(),
			CWE:             "CWE-1287",
		}}
	}

	findings := []Finding{
		{
			Rule:            "aibom-pickle-pytorch-zip",
			Severity:        SeverityInfo,
			Confidence:      ConfidenceHigh,
			ConfidenceLabel: ConfidenceHigh.String(),
			File:            path,
			Message:         "PyTorch ZIP archive detected — recursing into inner pickle entry",
		},
	}

	innerCount := 0
	for _, f := range zr.File {
		base := filepath.Base(f.Name)
		// Only analyse pickle entries — usually exactly "data.pkl".
		if base != "data.pkl" && !strings.HasSuffix(strings.ToLower(base), ".pkl") {
			continue
		}
		if innerCount >= maxInnerPickles {
			// Quadratic-DoS guard: refuse to expand more than maxInnerPickles
			// pickle entries from a single archive. A real PyTorch zip never
			// contains more than a handful.
			findings = append(findings, Finding{
				Rule:            "aibom-pickle-truncated",
				Severity:        SeverityWarning,
				Confidence:      ConfidenceHigh,
				ConfidenceLabel: ConfidenceHigh.String(),
				File:            path,
				Message: fmt.Sprintf(
					"PyTorch ZIP archive contains more than %d pickle entries — analysis halted",
					maxInnerPickles),
				CWE: "CWE-1287",
			})
			break
		}
		innerCount++
		rc, openErr := f.Open()
		if openErr != nil {
			continue
		}
		// Cap inner-stream size at 1 GiB to bound DoS via gzip-style amplification.
		inner, readErr := io.ReadAll(io.LimitReader(rc, maxByteArg))
		_ = rc.Close()
		if readErr != nil {
			continue
		}
		// Build a virtual path that points at the inner entry for clearer findings.
		innerPath := path + "::" + f.Name
		findings = append(findings, analyzePickleBytes(innerPath, inner, depth+1)...)
	}

	return findings
}

// ── disassembler ─────────────────────────────────────────────────────────────

// disassembler walks a single pickle byte-stream tracking only what is needed
// to identify GLOBAL / STACK_GLOBAL / REDUCE patterns.
type disassembler struct {
	path string
	data []byte
	pos  int

	// stack holds entries pushed by the opcode stream. Most entries are
	// scalar "data" placeholders (we keep them as nil to save memory); the
	// only entries we actually populate are GLOBAL references and tuples
	// of GLOBAL references — the structures REDUCE consumes.
	stack []stackEntry

	// memo maps memo-id → last entry stored via PUT/BINPUT/MEMOIZE. The
	// disassembler only uses the memo to track GLOBAL references survived
	// through GET/BINGET so REDUCE can be correlated with its callable.
	memo map[uint64]stackEntry

	// nextMemoID is the next id assigned by MEMOIZE. It increments on every
	// MEMOIZE (regardless of overwrites of existing ids by explicit BINPUT /
	// LONG_BINPUT) so we never collide on auto-assigned ids — matching CPython
	// pickle.py's Pickler.memoize() id-allocation semantics.
	nextMemoID uint64

	// found accumulates GLOBAL refs in order of appearance. Each ref records
	// the byte offset where it was emitted plus whether REDUCE consumed it.
	globals []globalRef

	// truncated is set when the stream ends before a STOP opcode.
	truncated bool
	// truncatedReason is a human-readable reason for the truncation.
	truncatedReason string
	// opcodeCount tracks the number of opcodes processed.
	opcodeCount int
	// hadOpcodeOverflow is set if we hit the maxOpcodes guard.
	hadOpcodeOverflow bool
}

// stackEntry is a tagged-union over the opcode-stack values we track.
type stackEntry struct {
	kind      stackKind
	qualified string       // populated for kindGlobal — "module.name"
	tuple     []stackEntry // populated for kindTuple
	mark      bool         // populated for kindMark
}

type stackKind uint8

const (
	kindData stackKind = iota
	kindGlobal
	kindString // arbitrary string we may need to recombine for STACK_GLOBAL
	kindTuple
	kindMark
)

// globalRef records a GLOBAL/STACK_GLOBAL reference for later finding emission.
type globalRef struct {
	qualified string
	offset    int
	reduced   bool // true when a REDUCE opcode consumed this callable
}

func newDisassembler(path string, data []byte) *disassembler {
	return &disassembler{
		path:    path,
		data:    data,
		stack:   make([]stackEntry, 0, 256),
		memo:    make(map[uint64]stackEntry, 64),
		globals: make([]globalRef, 0, 16),
	}
}

// run walks the stream until STOP, EOF, an overflow, or a fatal parse error.
// Errors are recorded as truncation; the disassembler never panics.
func (d *disassembler) run() {
	defer func() {
		// Defensive: a malformed stream must NEVER take down the scanner.
		if r := recover(); r != nil {
			d.truncated = true
			d.truncatedReason = fmt.Sprintf("panic during disassembly: %v", r)
		}
	}()

	for d.pos < len(d.data) {
		if d.opcodeCount >= maxOpcodes {
			d.hadOpcodeOverflow = true
			return
		}
		d.opcodeCount++

		op := d.data[d.pos]
		opOffset := d.pos
		d.pos++

		if op == opSTOP {
			return
		}
		if err := d.step(op, opOffset); err != nil {
			d.truncated = true
			d.truncatedReason = err.Error()
			return
		}
	}

	// Stream ended without STOP.
	d.truncated = true
	d.truncatedReason = "stream ended before STOP opcode"
}

// step interprets a single opcode. opOffset is the byte offset of `op`
// within the source stream — used for GLOBAL ref offsets in findings.
//
// Every branch advances d.pos past the opcode's argument bytes (if any).
// Branches that need to push a marker on the stack push a kindData unless
// the value is something we specifically track (GLOBAL, tuples, marks).
func (d *disassembler) step(op byte, opOffset int) error {
	switch op {

	// ── meta ────────────────────────────────────────────────────────────────

	case opPROTO:
		// 1-byte protocol version.
		if _, err := d.readN(1); err != nil {
			return err
		}

	case opFRAME:
		// 8-byte little-endian frame length. We don't enforce the frame
		// boundary — we just skip the header.
		if _, err := d.readN(8); err != nil {
			return err
		}

	case opMARK:
		d.push(stackEntry{kind: kindMark, mark: true})

	case opPOP:
		d.pop()

	case opPOPMARK:
		d.popMark()

	case opDUP:
		if len(d.stack) == 0 {
			return errors.New("DUP on empty stack")
		}
		d.push(d.stack[len(d.stack)-1])

	// ── primitives that just push opaque data ───────────────────────────────

	case opNONE, opNEWTRUE, opNEWFALSE, opEMPTY_DICT, opEMPTY_LIST, opEMPTY_TUPLE, opEMPTY_SET:
		d.push(stackEntry{kind: kindData})

	case opBININT:
		if _, err := d.readN(4); err != nil {
			return err
		}
		d.push(stackEntry{kind: kindData})
	case opBININT1:
		if _, err := d.readN(1); err != nil {
			return err
		}
		d.push(stackEntry{kind: kindData})
	case opBININT2:
		if _, err := d.readN(2); err != nil {
			return err
		}
		d.push(stackEntry{kind: kindData})
	case opBINFLOAT:
		if _, err := d.readN(8); err != nil {
			return err
		}
		d.push(stackEntry{kind: kindData})

	case opLONG1:
		ln, err := d.readN(1)
		if err != nil {
			return err
		}
		if _, err := d.readN(int(ln[0])); err != nil {
			return err
		}
		d.push(stackEntry{kind: kindData})
	case opLONG4:
		ln, err := d.readN(4)
		if err != nil {
			return err
		}
		n := int(int32(binary.LittleEndian.Uint32(ln)))
		if n < 0 || n > maxByteArg {
			return fmt.Errorf("LONG4 length out of range: %d", n)
		}
		if _, err := d.readN(n); err != nil {
			return err
		}
		d.push(stackEntry{kind: kindData})

	// ── text-format strings (NL-terminated) ─────────────────────────────────

	case opINT, opLONG, opFLOAT, opPERSID, opSTRING, opUNICODE:
		if _, err := d.readLine(); err != nil {
			return err
		}
		d.push(stackEntry{kind: kindData})

	case opGET:
		idx, err := d.readLine()
		if err != nil {
			return err
		}
		d.pushMemo(parseUintLine(idx))

	case opPUT:
		idx, err := d.readLine()
		if err != nil {
			return err
		}
		d.storeMemo(parseUintLine(idx))

	// ── binary length-prefixed payloads ─────────────────────────────────────

	case opBINSTRING, opBINBYTES:
		n, err := d.readUint32LE()
		if err != nil {
			return err
		}
		s, err := d.readN(int(n))
		if err != nil {
			return err
		}
		d.push(stackEntry{kind: kindString, qualified: bytesToString(s)})

	case opBINUNICODE:
		n, err := d.readUint32LE()
		if err != nil {
			return err
		}
		s, err := d.readN(int(n))
		if err != nil {
			return err
		}
		d.push(stackEntry{kind: kindString, qualified: bytesToString(s)})

	case opBINUNICODE8, opBINBYTES8, opBYTEARRAY8:
		n, err := d.readUint64LE()
		if err != nil {
			return err
		}
		if n > maxByteArg {
			return fmt.Errorf("8-byte length-prefixed arg too large: %d", n)
		}
		s, err := d.readN(int(n))
		if err != nil {
			return err
		}
		d.push(stackEntry{kind: kindString, qualified: bytesToString(s)})

	case opSHORT_BINSTRING, opSHORT_BINBYTES, opSHORT_BINUNICODE:
		ln, err := d.readN(1)
		if err != nil {
			return err
		}
		s, err := d.readN(int(ln[0]))
		if err != nil {
			return err
		}
		d.push(stackEntry{kind: kindString, qualified: bytesToString(s)})

	// ── memo ────────────────────────────────────────────────────────────────

	case opBINGET:
		ln, err := d.readN(1)
		if err != nil {
			return err
		}
		d.pushMemo(uint64(ln[0]))
	case opLONG_BINGET:
		idx, err := d.readUint32LE()
		if err != nil {
			return err
		}
		d.pushMemo(uint64(idx))
	case opBINPUT:
		ln, err := d.readN(1)
		if err != nil {
			return err
		}
		d.storeMemo(uint64(ln[0]))
	case opLONG_BINPUT:
		idx, err := d.readUint32LE()
		if err != nil {
			return err
		}
		d.storeMemo(uint64(idx))
	case opMEMOIZE:
		// Memoize the topmost stack item under the next available memo id.
		// Use a monotonic counter rather than len(d.memo) — the latter would
		// collide with ids previously written by BINPUT / LONG_BINPUT.
		id := d.nextMemoID
		d.nextMemoID++
		d.storeMemo(id)

	// ── containers / building ───────────────────────────────────────────────

	case opAPPEND:
		// Pop value, leave the list (data) on the stack.
		d.pop()
	case opAPPENDS, opSETITEMS, opADDITEMS:
		// Pop everything down to & including the topmost mark; the list/dict
		// remains underneath.
		d.popMark()
	case opSETITEM:
		// Pop key+value, leave dict.
		d.pop()
		d.pop()
	case opLIST, opDICT, opFROZENSET:
		// Replace mark...top with a single data entry.
		d.popMark()
		d.push(stackEntry{kind: kindData})

	case opTUPLE:
		// Replace mark...top with a single tuple entry. We keep the popped
		// items because REDUCE may inspect the args tuple.
		items := d.popUntilMark()
		d.push(stackEntry{kind: kindTuple, tuple: items})
	case opTUPLE1:
		if len(d.stack) >= 1 {
			top := d.stack[len(d.stack)-1]
			d.stack = d.stack[:len(d.stack)-1]
			d.push(stackEntry{kind: kindTuple, tuple: []stackEntry{top}})
		} else {
			d.push(stackEntry{kind: kindTuple})
		}
	case opTUPLE2:
		if len(d.stack) >= 2 {
			a := d.stack[len(d.stack)-2]
			b := d.stack[len(d.stack)-1]
			d.stack = d.stack[:len(d.stack)-2]
			d.push(stackEntry{kind: kindTuple, tuple: []stackEntry{a, b}})
		} else {
			d.push(stackEntry{kind: kindTuple})
		}
	case opTUPLE3:
		if len(d.stack) >= 3 {
			a := d.stack[len(d.stack)-3]
			b := d.stack[len(d.stack)-2]
			c := d.stack[len(d.stack)-1]
			d.stack = d.stack[:len(d.stack)-3]
			d.push(stackEntry{kind: kindTuple, tuple: []stackEntry{a, b, c}})
		} else {
			d.push(stackEntry{kind: kindTuple})
		}

	// ── persistence ─────────────────────────────────────────────────────────

	case opBINPERSID:
		// Pop the persistent id, push opaque data.
		d.pop()
		d.push(stackEntry{kind: kindData})

	// ── PROTOCOL EXTENSIONS — just consume their args ───────────────────────

	case opEXT1:
		if _, err := d.readN(1); err != nil {
			return err
		}
		d.push(stackEntry{kind: kindData})
	case opEXT2:
		if _, err := d.readN(2); err != nil {
			return err
		}
		d.push(stackEntry{kind: kindData})
	case opEXT4:
		if _, err := d.readN(4); err != nil {
			return err
		}
		d.push(stackEntry{kind: kindData})

	case opNEXT_BUFFER, opREADONLY_BUFFER:
		// Out-of-band buffer protocol — no operand bytes.

	// ── THE INTERESTING ONES ────────────────────────────────────────────────

	case opGLOBAL:
		// Two NL-terminated strings: module \n name \n.
		mod, err := d.readLine()
		if err != nil {
			return err
		}
		name, err := d.readLine()
		if err != nil {
			return err
		}
		qualified := strings.TrimSpace(string(mod)) + "." + strings.TrimSpace(string(name))
		d.recordGlobal(qualified, opOffset)
		d.push(stackEntry{kind: kindGlobal, qualified: qualified})

	case opSTACK_GLOBAL:
		// Pop name, pop module — both must be kindString entries pushed by
		// SHORT_BINUNICODE / BINUNICODE (or similar). If either is missing or
		// of the wrong kind, the stream is malformed; refuse to synthesise a
		// fake "." reference and let the truncation path emit a finding.
		name := d.pop()
		mod := d.pop()
		if name.kind != kindString || mod.kind != kindString {
			return errors.New("STACK_GLOBAL with malformed stack — name/module not kindString")
		}
		qualified := strings.TrimSpace(mod.qualified) + "." + strings.TrimSpace(name.qualified)
		d.recordGlobal(qualified, opOffset)
		d.push(stackEntry{kind: kindGlobal, qualified: qualified})

	case opINST:
		// INST has TWO NL-terminated args (module \n name \n) followed by
		// a stack-popping behaviour for the constructor's positional args.
		mod, err := d.readLine()
		if err != nil {
			return err
		}
		name, err := d.readLine()
		if err != nil {
			return err
		}
		qualified := strings.TrimSpace(string(mod)) + "." + strings.TrimSpace(string(name))
		d.recordGlobal(qualified, opOffset)
		// INST consumes args between the topmost mark and TOS. We
		// approximate by popping until mark.
		_ = d.popUntilMark()
		// Mark this global as "reduced" — INST is itself a callable apply.
		d.markLastGlobalReduced(qualified)
		d.push(stackEntry{kind: kindData})

	case opOBJ:
		// OBJ pops everything up to and including the topmost mark. The
		// topmost item before the args is the class. Treat that GLOBAL as
		// reduced.
		items := d.popUntilMark()
		if len(items) > 0 && items[0].kind == kindGlobal {
			d.markLastGlobalReduced(items[0].qualified)
		}
		d.push(stackEntry{kind: kindData})

	case opNEWOBJ:
		// Pop argtuple, pop cls, push data. Treat the cls as reduced.
		_ = d.pop() // argtuple
		cls := d.pop()
		if cls.kind == kindGlobal {
			d.markLastGlobalReduced(cls.qualified)
		}
		d.push(stackEntry{kind: kindData})

	case opNEWOBJ_EX:
		// Pop kwargs, pop argtuple, pop cls, push data.
		_ = d.pop()
		_ = d.pop()
		cls := d.pop()
		if cls.kind == kindGlobal {
			d.markLastGlobalReduced(cls.qualified)
		}
		d.push(stackEntry{kind: kindData})

	case opREDUCE:
		// Pop argtuple, pop callable, push opaque data.
		_ = d.pop() // argtuple
		callable := d.pop()
		if callable.kind == kindGlobal {
			d.markLastGlobalReduced(callable.qualified)
		}
		d.push(stackEntry{kind: kindData})

	case opBUILD:
		// BUILD pops state, leaves obj on the stack.
		d.pop()

	default:
		// Unknown opcode — bail rather than risk skipping bytes incorrectly.
		return fmt.Errorf("unknown opcode 0x%02x at offset 0x%X", op, opOffset)
	}

	if len(d.stack) > maxStackSize {
		return fmt.Errorf("stack depth exceeded %d", maxStackSize)
	}
	return nil
}

// ── stack helpers ────────────────────────────────────────────────────────────

func (d *disassembler) push(e stackEntry) {
	d.stack = append(d.stack, e)
}

func (d *disassembler) pop() stackEntry {
	if len(d.stack) == 0 {
		return stackEntry{kind: kindData}
	}
	top := d.stack[len(d.stack)-1]
	d.stack = d.stack[:len(d.stack)-1]
	return top
}

// popUntilMark pops items up to and including the topmost mark. The popped
// items above the mark are returned in stack order (oldest first).
func (d *disassembler) popUntilMark() []stackEntry {
	for i := len(d.stack) - 1; i >= 0; i-- {
		if d.stack[i].mark {
			items := append([]stackEntry(nil), d.stack[i+1:]...)
			d.stack = d.stack[:i]
			return items
		}
	}
	// No mark on stack — common with malformed pickles. Drain stack.
	items := append([]stackEntry(nil), d.stack...)
	d.stack = d.stack[:0]
	return items
}

// popMark pops up to and including the topmost mark; discards the items.
func (d *disassembler) popMark() {
	for i := len(d.stack) - 1; i >= 0; i-- {
		if d.stack[i].mark {
			d.stack = d.stack[:i]
			return
		}
	}
	// No mark — drain.
	d.stack = d.stack[:0]
}

func (d *disassembler) storeMemo(id uint64) {
	if len(d.stack) == 0 {
		return
	}
	d.memo[id] = d.stack[len(d.stack)-1]
}

func (d *disassembler) pushMemo(id uint64) {
	if entry, ok := d.memo[id]; ok {
		d.push(entry)
		return
	}
	d.push(stackEntry{kind: kindData})
}

// ── byte-stream helpers ──────────────────────────────────────────────────────

func (d *disassembler) readN(n int) ([]byte, error) {
	if n < 0 {
		return nil, fmt.Errorf("negative read length: %d", n)
	}
	if n > maxByteArg {
		return nil, fmt.Errorf("read length too large: %d", n)
	}
	if d.pos+n > len(d.data) {
		return nil, fmt.Errorf("short read at offset 0x%X (need %d bytes)", d.pos, n)
	}
	buf := d.data[d.pos : d.pos+n]
	d.pos += n
	return buf, nil
}

// readLine reads up through the next 0x0A (newline) byte and returns the
// content WITHOUT the trailing newline.
func (d *disassembler) readLine() ([]byte, error) {
	idx := bytes.IndexByte(d.data[d.pos:], '\n')
	if idx < 0 {
		return nil, fmt.Errorf("missing newline-terminated arg at offset 0x%X", d.pos)
	}
	line := d.data[d.pos : d.pos+idx]
	d.pos += idx + 1
	return line, nil
}

func (d *disassembler) readUint32LE() (uint32, error) {
	b, err := d.readN(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

func (d *disassembler) readUint64LE() (uint64, error) {
	b, err := d.readN(8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b), nil
}

// ── recording / emitting ─────────────────────────────────────────────────────

func (d *disassembler) recordGlobal(qualified string, offset int) {
	d.globals = append(d.globals, globalRef{qualified: qualified, offset: offset})
}

// markLastGlobalReduced flags the most-recent unreduced ref with this name as
// having been consumed by REDUCE/INST/OBJ/NEWOBJ. It only affects rule selection
// (we use it to fire aibom-pickle-reduce-suspicious for non-allowlisted callables).
func (d *disassembler) markLastGlobalReduced(qualified string) {
	for i := len(d.globals) - 1; i >= 0; i-- {
		if d.globals[i].qualified == qualified && !d.globals[i].reduced {
			d.globals[i].reduced = true
			return
		}
	}
}

// emit converts collected globals + stream state into Findings.
func (d *disassembler) emit() []Finding {
	var findings []Finding

	if d.hadOpcodeOverflow {
		findings = append(findings, Finding{
			Rule:            "aibom-pickle-truncated",
			Severity:        SeverityWarning,
			Confidence:      ConfidenceHigh,
			ConfidenceLabel: ConfidenceHigh.String(),
			File:            d.path,
			Message:         fmt.Sprintf("pickle stream exceeded %d opcodes — disassembly halted", maxOpcodes),
			CWE:             "CWE-1287",
		})
	} else if d.truncated {
		findings = append(findings, Finding{
			Rule:            "aibom-pickle-truncated",
			Severity:        SeverityWarning,
			Confidence:      ConfidenceHigh,
			ConfidenceLabel: ConfidenceHigh.String(),
			File:            d.path,
			Message:         "pickle stream truncated or malformed: " + d.truncatedReason,
			CWE:             "CWE-1287",
		})
	}

	// One Finding per recorded GLOBAL — classified by qualified name.
	dangerousSeen := false
	for _, g := range d.globals {
		f, ok := classifyGlobal(d.path, g)
		if !ok {
			continue
		}
		if f.Severity >= SeverityHigh {
			dangerousSeen = true
		}
		findings = append(findings, f)
	}

	// If the file ONLY contains allowlisted ML globals, surface a single
	// summary INFO so the report is not silent on safe files.
	if !dangerousSeen && len(d.globals) > 0 && allOnlyAllowlisted(d.globals) {
		findings = append(findings, Finding{
			Rule:            "aibom-pickle-allowlisted",
			Severity:        SeverityInfo,
			Confidence:      ConfidenceHigh,
			ConfidenceLabel: ConfidenceHigh.String(),
			File:            d.path,
			Message:         fmt.Sprintf("pickle contains only allowlisted ML globals (%d refs) — appears safe", len(d.globals)),
		})
	}

	return findings
}

// classifyGlobal returns a Finding for the given global ref, plus a bool
// signalling whether the ref produced a finding at all (some globals — those
// matching allowlist AND not reduced suspiciously — produce nothing here;
// their summary is emitted by allOnlyAllowlisted at the file level).
func classifyGlobal(path string, g globalRef) (Finding, bool) {
	q := g.qualified

	// Critical tier — always emits, regardless of REDUCE.
	if rationale, ok := patterns.DangerousGlobalsCritical[q]; ok {
		return Finding{
			Rule:            ruleForCritical(q),
			Severity:        SeverityCritical,
			Confidence:      ConfidenceHigh,
			ConfidenceLabel: ConfidenceHigh.String(),
			File:            path,
			Message: fmt.Sprintf(
				"dangerous pickle GLOBAL %q at offset 0x%X — %s (CWE-502)",
				q, g.offset, rationale),
			CWE: cweForCritical(q),
		}, true
	}

	// High tier — network egress.
	if rationale, ok := patterns.DangerousGlobalsHigh[q]; ok {
		return Finding{
			Rule:            "aibom-pickle-network",
			Severity:        SeverityHigh,
			Confidence:      ConfidenceHigh,
			ConfidenceLabel: ConfidenceHigh.String(),
			File:            path,
			Message: fmt.Sprintf(
				"network-capable GLOBAL %q at offset 0x%X — %s (CWE-502)",
				q, g.offset, rationale),
			CWE: "CWE-502",
		}, true
	}

	// Medium tier — destructive filesystem. Filesystem destruction is
	// concerning but not in the same league as RCE (Critical) or network
	// egress (High); emit at WARNING to match the documented tier semantics
	// in patterns/aibom.go.
	if rationale, ok := patterns.DangerousGlobalsMedium[q]; ok {
		return Finding{
			Rule:            "aibom-pickle-filesystem",
			Severity:        SeverityWarning,
			Confidence:      ConfidenceMedium,
			ConfidenceLabel: ConfidenceMedium.String(),
			File:            path,
			Message: fmt.Sprintf(
				"destructive-filesystem GLOBAL %q at offset 0x%X — %s (CWE-502)",
				q, g.offset, rationale),
			CWE: "CWE-502",
		}, true
	}

	// Allowlisted — produce no per-ref finding (a single summary fires later).
	if patterns.IsAllowedMLGlobal(q) {
		return Finding{}, false
	}

	// Unknown global — only flag if REDUCE consumed it. A bare GLOBAL
	// without REDUCE is usually a class reference that pickle uses to
	// reconstruct an instance; flagging every one would be noisy.
	if g.reduced {
		return Finding{
			Rule:            "aibom-pickle-reduce-suspicious",
			Severity:        SeverityHigh,
			Confidence:      ConfidenceMedium,
			ConfidenceLabel: ConfidenceMedium.String(),
			File:            path,
			Message: fmt.Sprintf(
				"REDUCE invokes non-allowlisted GLOBAL %q at offset 0x%X (CWE-502)",
				q, g.offset),
			CWE: "CWE-502",
		}, true
	}

	return Finding{}, false
}

// allOnlyAllowlisted returns true when every ref is in the ML allowlist.
func allOnlyAllowlisted(refs []globalRef) bool {
	for _, r := range refs {
		if !patterns.IsAllowedMLGlobal(r.qualified) {
			return false
		}
	}
	return true
}

// ── rule-id mapping for critical tier ───────────────────────────────────────

func ruleForCritical(qualified string) string {
	switch {
	case strings.HasPrefix(qualified, "os.system"),
		strings.HasPrefix(qualified, "os.popen"),
		strings.HasPrefix(qualified, "posix.system"),
		strings.HasPrefix(qualified, "posix.popen"),
		strings.HasPrefix(qualified, "nt.system"),
		strings.HasPrefix(qualified, "commands."),
		qualified == "pty.spawn":
		return "aibom-pickle-os-system"
	case strings.HasPrefix(qualified, "subprocess."):
		return "aibom-pickle-subprocess"
	case qualified == "builtins.eval", qualified == "builtins.exec", qualified == "builtins.compile",
		qualified == "__builtin__.eval", qualified == "__builtin__.exec", qualified == "__builtin__.compile":
		return "aibom-pickle-eval-exec"
	case qualified == "builtins.__import__", qualified == "__builtin__.__import__",
		strings.HasPrefix(qualified, "importlib."):
		return "aibom-pickle-import"
	case strings.HasPrefix(qualified, "runpy."):
		return "aibom-pickle-runpy"
	default:
		return "aibom-pickle-reduce-suspicious"
	}
}

// cweForCritical picks the most accurate CWE for a critical-tier global.
// builtins.eval/exec/compile is CWE-94 (code injection); everything else
// in the critical tier is CWE-502 (deserialization of untrusted data).
func cweForCritical(qualified string) string {
	switch qualified {
	case "builtins.eval", "builtins.exec", "builtins.compile",
		"__builtin__.eval", "__builtin__.exec", "__builtin__.compile":
		return "CWE-94"
	}
	return "CWE-502"
}

// ── small utilities ─────────────────────────────────────────────────────────

// bytesToString converts bytes to string without an extra allocation.
// We keep it inline rather than using unsafe — the strings are tiny so this
// helper exists purely for clarity.
func bytesToString(b []byte) string {
	return string(b)
}

// parseUintLine parses an ASCII unsigned integer line as used by the text
// PUT/GET opcodes. Garbage input parses to 0 — the disassembler is
// best-effort and the worst case is a memo miss.
func parseUintLine(b []byte) uint64 {
	var n uint64
	for _, c := range b {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + uint64(c-'0')
	}
	return n
}
