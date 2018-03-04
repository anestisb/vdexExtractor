/*

   vdexExtractor
   -----------------------------------------

   Anestis Bechtsoudis <anestis@census-labs.com>
   Copyright 2017 - 2018 by CENSUS S.A. All Rights Reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

*/

#ifndef _DEX_INSTRUCTION_H_
#define _DEX_INSTRUCTION_H_

#include "common.h"
#include "dex_instruction_list.h"

typedef enum {
  kPackedSwitchSignature = 0x0100,
  kSparseSwitchSignature = 0x0200,
  kArrayDataSignature = 0x0300,
} Signatures;

// clang-format off

typedef enum {
#define INSTRUCTION_ENUM(opcode, cname, p, f, i, a, e, v) cname = (opcode),
  DEX_INSTRUCTION_LIST(INSTRUCTION_ENUM)
  RSUB_INT_LIT16 = RSUB_INT,
} Code;

// clang-format on

typedef enum {
  k10x,  // op
  k12x,  // op vA, vB
  k11n,  // op vA, #+B
  k11x,  // op vAA
  k10t,  // op +AA
  k20t,  // op +AAAA
  k22x,  // op vAA, vBBBB
  k21t,  // op vAA, +BBBB
  k21s,  // op vAA, #+BBBB
  k21h,  // op vAA, #+BBBB00000[00000000]
  k21c,  // op vAA, thing@BBBB
  k23x,  // op vAA, vBB, vCC
  k22b,  // op vAA, vBB, #+CC
  k22t,  // op vA, vB, +CCCC
  k22s,  // op vA, vB, #+CCCC
  k22c,  // op vA, vB, thing@CCCC
  k32x,  // op vAAAA, vBBBB
  k30t,  // op +AAAAAAAA
  k31t,  // op vAA, +BBBBBBBB
  k31i,  // op vAA, #+BBBBBBBB
  k31c,  // op vAA, thing@BBBBBBBB
  k35c,  // op {vC, vD, vE, vF, vG}, thing@BBBB (B: count, A: vG)
  k3rc,  // op {vCCCC .. v(CCCC+AA-1)}, meth@BBBB

  // op {vC, vD, vE, vF, vG}, meth@BBBB, proto@HHHH (A: count)
  // format: AG op BBBB FEDC HHHH
  k45cc,

  // op {VCCCC .. v(CCCC+AA-1)}, meth@BBBB, proto@HHHH (AA: count)
  // format: AA op BBBB CCCC HHHH
  k4rcc,  // op {VCCCC .. v(CCCC+AA-1)}, meth@BBBB, proto@HHHH (AA: count)

  k51l,  // op vAA, #+BBBBBBBBBBBBBBBB
} Format;

typedef enum {
  kIndexUnknown = 0,
  kIndexNone,               // has no index
  kIndexTypeRef,            // type reference index
  kIndexStringRef,          // string reference index
  kIndexMethodRef,          // method reference index
  kIndexFieldRef,           // field reference index
  kIndexFieldOffset,        // field offset (for static linked fields)
  kIndexVtableOffset,       // vtable offset (for static linked methods)
  kIndexMethodAndProtoRef,  // method and a proto reference index (for invoke-polymorphic)
  kIndexCallSiteRef,        // call site reference index
  kIndexMethodHandleRef,    // constant method handle reference index
  kIndexProtoRef,           // prototype reference index
} IndexType;

typedef enum {
  kBranch = 0x01,         // conditional or unconditional branch
  kContinue = 0x02,       // flow can continue to next statement
  kSwitch = 0x04,         // switch statement
  kThrow = 0x08,          // could cause an exception to be thrown
  kReturn = 0x10,         // returns, no additional statements
  kInvoke = 0x20,         // a flavor of invoke
  kUnconditional = 0x40,  // unconditional branch
  kExperimental = 0x80,   // is an experimental opcode
} Flags;

typedef enum {
  kAdd = 0x0000080,        // addition
  kSubtract = 0x0000100,   // subtract
  kMultiply = 0x0000200,   // multiply
  kDivide = 0x0000400,     // division
  kRemainder = 0x0000800,  // remainder
  kAnd = 0x0001000,        // and
  kOr = 0x0002000,         // or
  kXor = 0x0004000,        // xor
  kShl = 0x0008000,        // shl
  kShr = 0x0010000,        // shr
  kUshr = 0x0020000,       // ushr
  kCast = 0x0040000,       // cast
  kStore = 0x0080000,      // store opcode
  kLoad = 0x0100000,       // load opcode
  kClobber = 0x0200000,    // clobbers memory in a big way (not just a write)
  kRegCFieldOrConstant =
      0x0400000,  // is the third virtual register a field or literal constant (vC)
  kRegBFieldOrConstant =
      0x0800000,  // is the second virtual register a field or literal constant (vB)
} ExtendedFlags;

typedef enum {
  kVerifyNone = 0x0000000,
  kVerifyRegA = 0x0000001,
  kVerifyRegAWide = 0x0000002,
  kVerifyRegB = 0x0000004,
  kVerifyRegBField = 0x0000008,
  kVerifyRegBMethod = 0x0000010,
  kVerifyRegBNewInstance = 0x0000020,
  kVerifyRegBString = 0x0000040,
  kVerifyRegBType = 0x0000080,
  kVerifyRegBWide = 0x0000100,
  kVerifyRegC = 0x0000200,
  kVerifyRegCField = 0x0000400,
  kVerifyRegCNewArray = 0x0000800,
  kVerifyRegCType = 0x0001000,
  kVerifyRegCWide = 0x0002000,
  kVerifyArrayData = 0x0004000,
  kVerifyBranchTarget = 0x0008000,
  kVerifySwitchTargets = 0x0010000,
  kVerifyVarArg = 0x0020000,
  kVerifyVarArgNonZero = 0x0040000,
  kVerifyVarArgRange = 0x0080000,
  kVerifyVarArgRangeNonZero = 0x0100000,
  kVerifyRuntimeOnly = 0x0200000,
  kVerifyError = 0x0400000,
  kVerifyRegHPrototype = 0x0800000,
  kVerifyRegBCallSite = 0x1000000,
  kVerifyRegBMethodHandle = 0x2000000,
  kVerifyRegBPrototype = 0x4000000,
} VerifyFlag;

typedef struct {
  u4 verify_flags;
  Format format;
  IndexType index_type;
  u1 flags;
  s1 size_in_code_units;
} instrDesc_t;

static const u4 kMaxVarArgRegs = 5;

// clang-format off

static const char *const kInstructionNames[] = {
#define INSTRUCTION_NAME(o, c, pname, f, i, a, e, v) pname,
  DEX_INSTRUCTION_LIST(INSTRUCTION_NAME)
};

#define INSTRUCTION_SIZE(opcode, format) \
    (((opcode) == NOP) ? -1 : \
     (((format) >= k10x) && ((format) <= k10t)) ?  1 : \
     (((format) >= k20t) && ((format) <= k22c)) ?  2 : \
     (((format) >= k32x) && ((format) <= k3rc)) ?  3 : \
     (((format) >= k45cc) && ((format) <= k4rcc)) ? 4 : \
      ((format) == k51l) ?  5 : -1)

static instrDesc_t const kInstructionDescriptors[] = {
#define INSTRUCTION_DESCR(opcode, c, p, format, index, flags, eflags, vflags) \
  {  vflags, \
     format, \
     index, \
     flags, \
     INSTRUCTION_SIZE((c), (format)), \
  },
  DEX_INSTRUCTION_LIST(INSTRUCTION_DESCR)
};

// clang-format on

// Instruction opcode functions
Code dexInstr_getOpcode(u2 *);
const char *dexInst_getOpcodeStr(u2 *);
void dexInstr_SetOpcode(u2 *, Code);

// VRegA
bool dexInstr_hasVRegA(u2 *);
s4 dexInstr_getVRegA(u2 *);
s1 dexInstr_getVRegA_10t(u2 *);
u1 dexInstr_getVRegA_10x(u2 *);
u1 dexInstr_getVRegA_11n(u2 *);
u1 dexInstr_getVRegA_11x(u2 *);
u1 dexInstr_getVRegA_12x(u2 *);
s2 dexInstr_getVRegA_20t(u2 *);
u1 dexInstr_getVRegA_21c(u2 *);
u1 dexInstr_getVRegA_21h(u2 *);
u1 dexInstr_getVRegA_21s(u2 *);
u1 dexInstr_getVRegA_21t(u2 *);
u1 dexInstr_getVRegA_22b(u2 *);
u1 dexInstr_getVRegA_22c(u2 *);
u1 dexInstr_getVRegA_22s(u2 *);
u1 dexInstr_getVRegA_22t(u2 *);
u1 dexInstr_getVRegA_22x(u2 *);
u1 dexInstr_getVRegA_23x(u2 *);
s4 dexInstr_getVRegA_30t(u2 *);
u1 dexInstr_getVRegA_31c(u2 *);
u1 dexInstr_getVRegA_31i(u2 *);
u1 dexInstr_getVRegA_31t(u2 *);
u2 dexInstr_getVRegA_32x(u2 *);
u1 dexInstr_getVRegA_35c(u2 *);
u1 dexInstr_getVRegA_3rc(u2 *);
u1 dexInstr_getVRegA_51l(u2 *);
u1 dexInstr_getVRegA_45cc(u2 *);
u1 dexInstr_getVRegA_4rcc(u2 *);

// VRegB
bool dexInstr_hasVRegB(u2 *);
s4 dexInstr_getVRegB(u2 *);
u8 dexInstr_getWideVRegB(u2 *);
s1 dexInstr_getVRegB_11n(u2 *);
u1 dexInstr_getVRegB_12x(u2 *);
u2 dexInstr_getVRegB_21c(u2 *);
u2 dexInstr_getVRegB_21h(u2 *);
s2 dexInstr_getVRegB_21s(u2 *);
s2 dexInstr_getVRegB_21t(u2 *);
u1 dexInstr_getVRegB_22b(u2 *);
u1 dexInstr_getVRegB_22c(u2 *);
u1 dexInstr_getVRegB_22s(u2 *);
u1 dexInstr_getVRegB_22t(u2 *);
u2 dexInstr_getVRegB_22x(u2 *);
u1 dexInstr_getVRegB_23x(u2 *);
u4 dexInstr_getVRegB_31c(u2 *);
s4 dexInstr_getVRegB_31i(u2 *);
s4 dexInstr_getVRegB_31t(u2 *);
u2 dexInstr_getVRegB_32x(u2 *);
u2 dexInstr_getVRegB_35c(u2 *);
u2 dexInstr_getVRegB_3rc(u2 *);
u2 dexInstr_getVRegB_45cc(u2 *);
u2 dexInstr_getVRegB_4rcc(u2 *);
u8 dexInstr_getVRegB_51l(u2 *);

// VRegC
bool dexInstr_hasVRegC(u2 *);
s4 dexInstr_getVRegC(u2 *);
s1 dexInstr_getVRegC_22b(u2 *);
u2 dexInstr_getVRegC_22c(u2 *);
s2 dexInstr_getVRegC_22s(u2 *);
s2 dexInstr_getVRegC_22t(u2 *);
u1 dexInstr_getVRegC_23x(u2 *);
u1 dexInstr_getVRegC_35c(u2 *);
u2 dexInstr_getVRegC_3rc(u2 *);
u1 dexInstr_getVRegC_45cc(u2 *);
u2 dexInstr_getVRegC_4rcc(u2 *);

// VRegH
bool dexInstr_hasVRegH(u2 *);
s4 dexInstr_getVRegH(u2 *);
u2 dexInstr_getVRegH_45cc(u2 *);
u2 dexInstr_getVRegH_4rcc(u2 *);
bool dexInstr_hasVarArgs(u2 *);
void dexInstr_getVarArgs(u2 *, u4[]);

// Set register functions
void dexInstr_SetVRegA_10x(u2 *, u1);
void dexInstr_SetVRegB_3rc(u2 *, u2);
void dexInstr_SetVRegB_35c(u2 *, u2);
void dexInstr_SetVRegC_22c(u2 *, u2);
void dexInstr_SetVRegA_21c(u2 *, u1);
void dexInstr_SetVRegB_21c(u2 *, u2);

bool dexInstr_isBranch(u2 *);
bool dexInstr_isUnconditional(u2 *);
bool dexInstr_isQuickened(u2 *);
bool dexInstr_isSwitch(u2 *);
bool dexInstr_isThrow(u2 *);
bool dexInstr_isReturn(u2 *);
bool dexInstr_isBasicBlockEnd(u2 *);
bool dexInstr_isInvoke(u2 *);

// Returns the size (in 2 byte code units) of this instruction.
u4 dexInstr_SizeInCodeUnits(u2 *);

// Global exported arrays with constants
extern const char *const kInstructionNames[];
extern instrDesc_t const kInstructionDescriptors[];

#endif
