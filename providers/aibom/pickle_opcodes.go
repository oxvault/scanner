package aibom

// Pickle opcode constants for protocols 0 through 5.
//
// These match Python's stdlib pickle module (Lib/pickle.py) byte-for-byte. The
// disassembler reads a stream of these opcodes WITHOUT executing any embedded
// callables — see pickle.go.
//
// Reference:
//
//	https://github.com/python/cpython/blob/main/Lib/pickle.py (search for "OPCODE")
//	https://github.com/python/cpython/blob/main/Lib/pickletools.py
//
// Opcode bytes are grouped by the protocol version that introduced them.
const (
	// ── Protocol 0 (text-based) ───────────────────────────────────────────────

	opMARK            = '('  // push special markobject on stack
	opSTOP            = '.'  // every pickle ends with STOP
	opPOP             = '0'  // discard topmost stack item
	opPOPMARK         = '1'  // discard stack top through topmost markobject
	opDUP             = '2'  // duplicate top stack item
	opFLOAT           = 'F'  // push float object; decimal string argument
	opINT             = 'I'  // push integer or bool; decimal string argument
	opBININT          = 'J'  // push 4-byte signed int
	opBININT1         = 'K'  // push 1-byte unsigned int
	opLONG            = 'L'  // push long; decimal string argument
	opBININT2         = 'M'  // push 2-byte unsigned int
	opNONE            = 'N'  // push None
	opPERSID          = 'P'  // push persistent object; id is taken from string arg
	opBINPERSID       = 'Q'  //  "       "         "  ;  "  "   "     "  stack
	opREDUCE          = 'R'  // apply callable to argtuple, both on stack
	opSTRING          = 'S'  // push string; NL-terminated string argument
	opBINSTRING       = 'T'  // push string; counted binary string argument
	opSHORT_BINSTRING = 'U'  //  "     "   ;    "      "       "      " < 256 bytes
	opUNICODE         = 'V'  // push Unicode string; raw-unicode-escaped'd argument
	opBINUNICODE      = 'X'  //   "     "       "  ; counted UTF-8 string argument
	opAPPEND          = 'a'  // append stack top to list below it
	opBUILD           = 'b'  // call __setstate__ or __dict__.update()
	opGLOBAL          = 'c'  // push self.find_class(modname, name); 2 string args
	opDICT            = 'd'  // build a dict from stack items
	opEMPTY_DICT      = '}'  // push empty dict
	opAPPENDS         = 'e'  // extend list on stack by topmost stack slice
	opGET             = 'g'  // push item from memo on stack; index is string arg
	opBINGET          = 'h'  //   "    "    "    "   "   "    "    "    "  1-byte arg
	opINST            = 'i'  // build & push class instance
	opLONG_BINGET     = 'j'  // push item from memo on stack; index is 4-byte arg
	opLIST            = 'l'  // build list from topmost stack items
	opEMPTY_LIST      = ']'  // push empty list
	opOBJ             = 'o'  // build & push class instance
	opPUT             = 'p'  // store stack top in memo; index is string arg
	opBINPUT          = 'q'  //   "    "  "   "    "   ;   "  " 1-byte arg
	opLONG_BINPUT     = 'r'  //   "    "  "   "    "   ;   "  " 4-byte arg
	opSETITEM         = 's'  // add key+value pair to dict
	opTUPLE           = 't'  // build tuple from topmost stack items
	opEMPTY_TUPLE     = ')'  // push empty tuple
	opSETITEMS        = 'u'  // modify dict by adding topmost key+value pairs
	opBINFLOAT        = 'G'  // push float; arg is 8-byte float encoding

	// ── Protocol 1 (binary) ───────────────────────────────────────────────────

	opPROTO    = '\x80' // identify pickle protocol
	opNEWOBJ   = '\x81' // build object by applying cls.__new__ to argtuple
	opEXT1     = '\x82' // push object from extension registry; 1-byte index
	opEXT2     = '\x83' // ditto, but 2-byte index
	opEXT4     = '\x84' // ditto, but 4-byte index
	opTUPLE1   = '\x85' // build 1-tuple from stack top
	opTUPLE2   = '\x86' // build 2-tuple from two topmost stack items
	opTUPLE3   = '\x87' // build 3-tuple from three topmost stack items
	opNEWTRUE  = '\x88' // push True
	opNEWFALSE = '\x89' // push False
	opLONG1    = '\x8a' // push long from < 256 bytes
	opLONG4    = '\x8b' // push really big long

	// ── Protocol 2 ────────────────────────────────────────────────────────────
	// (reuses opcodes 0x80-0x8B already declared above)

	// ── Protocol 3 ────────────────────────────────────────────────────────────

	opBINBYTES       = 'B' // push bytes; counted binary string argument
	opSHORT_BINBYTES = 'C' // push bytes; counted binary string argument < 256 bytes

	// ── Protocol 4 ────────────────────────────────────────────────────────────

	opSHORT_BINUNICODE = '\x8c' // push short Unicode string; UTF-8 length < 256 bytes
	opBINUNICODE8      = '\x8d' // push very long Unicode string
	opBINBYTES8        = '\x8e' // push very long bytes string
	opEMPTY_SET        = '\x8f' // push empty set on the stack
	opADDITEMS         = '\x90' // modify set by adding topmost stack items
	opFROZENSET        = '\x91' // build frozenset from topmost stack items
	opNEWOBJ_EX        = '\x92' // like NEWOBJ but work with keyword only arguments
	opSTACK_GLOBAL     = '\x93' // same as GLOBAL but using names on the stacks
	opMEMOIZE          = '\x94' // store top of the stack in memo
	opFRAME            = '\x95' // indicate the beginning of a new frame

	// ── Protocol 5 ────────────────────────────────────────────────────────────

	opBYTEARRAY8     = '\x96' // push bytearray
	opNEXT_BUFFER    = '\x97' // push next out-of-band buffer
	opREADONLY_BUFFER = '\x98' // make top of stack readonly
)

