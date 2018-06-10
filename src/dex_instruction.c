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

#include "dex_instruction.h"

static u4 SizeInCodeUnitsComplexOpcode(u2 *code_ptr) {
  // Handle special NOP encoded variable length sequences.
  switch (*code_ptr) {
    case kPackedSwitchSignature:
      return (4 + code_ptr[1] * 2);
    case kSparseSwitchSignature:
      return (2 + code_ptr[1] * 4);
    case kArrayDataSignature: {
      u2 element_size = code_ptr[1];
      u4 length = code_ptr[2] | (((u4)code_ptr[3]) << 16);
      // The plus 1 is to round up for odd size and width.
      return (4 + (element_size * length + 1) / 2);
    }
    default:
      if ((*code_ptr & 0xFF) == 0) {
        return 1;  // NOP.
      } else {
        LOGMSG(l_FATAL, "Error when decoding complex opcode");
        exitWrapper(EXIT_FAILURE);
        return 0;  // Silence "-Wreturn-type"
      }
  }
}

static u1 InstAA(u2 *code_ptr) { return code_ptr[0] >> 8; }

static u1 InstA(u2 *code_ptr) { return (code_ptr[0] >> 8) & 0x0f; }

static u1 InstB(u2 *code_ptr) { return code_ptr[0] >> 12; }

Code dexInstr_getOpcode(u2 *code_ptr) { return (code_ptr[0] & 0xFF); }

const char *dexInst_getOpcodeStr(u2 *code_ptr) {
  return kInstructionNames[dexInstr_getOpcode(code_ptr)];
}

void dexInstr_SetOpcode(u2 *code_ptr, Code opcode) {
  CHECK_LT(opcode, 256u);
  code_ptr[0] = (code_ptr[0] & 0xff00) | opcode;
}

bool dexInstr_hasVRegA(u2 *code_ptr) {
  switch (kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format) {
    case k10t:
      return true;
    case k10x:
      return true;
    case k11n:
      return true;
    case k11x:
      return true;
    case k12x:
      return true;
    case k20t:
      return true;
    case k21c:
      return true;
    case k21h:
      return true;
    case k21s:
      return true;
    case k21t:
      return true;
    case k22b:
      return true;
    case k22c:
      return true;
    case k22s:
      return true;
    case k22t:
      return true;
    case k22x:
      return true;
    case k23x:
      return true;
    case k30t:
      return true;
    case k31c:
      return true;
    case k31i:
      return true;
    case k31t:
      return true;
    case k32x:
      return true;
    case k35c:
      return true;
    case k3rc:
      return true;
    case k45cc:
      return true;
    case k4rcc:
      return true;
    case k51l:
      return true;
    default:
      return false;
  }
}

s4 dexInstr_getVRegA(u2 *code_ptr) {
  switch (kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format) {
    case k10t:
      return dexInstr_getVRegA_10t(code_ptr);
    case k10x:
      return dexInstr_getVRegA_10x(code_ptr);
    case k11n:
      return dexInstr_getVRegA_11n(code_ptr);
    case k11x:
      return dexInstr_getVRegA_11x(code_ptr);
    case k12x:
      return dexInstr_getVRegA_12x(code_ptr);
    case k20t:
      return dexInstr_getVRegA_20t(code_ptr);
    case k21c:
      return dexInstr_getVRegA_21c(code_ptr);
    case k21h:
      return dexInstr_getVRegA_21h(code_ptr);
    case k21s:
      return dexInstr_getVRegA_21s(code_ptr);
    case k21t:
      return dexInstr_getVRegA_21t(code_ptr);
    case k22b:
      return dexInstr_getVRegA_22b(code_ptr);
    case k22c:
      return dexInstr_getVRegA_22c(code_ptr);
    case k22s:
      return dexInstr_getVRegA_22s(code_ptr);
    case k22t:
      return dexInstr_getVRegA_22t(code_ptr);
    case k22x:
      return dexInstr_getVRegA_22x(code_ptr);
    case k23x:
      return dexInstr_getVRegA_23x(code_ptr);
    case k30t:
      return dexInstr_getVRegA_30t(code_ptr);
    case k31c:
      return dexInstr_getVRegA_31c(code_ptr);
    case k31i:
      return dexInstr_getVRegA_31i(code_ptr);
    case k31t:
      return dexInstr_getVRegA_31t(code_ptr);
    case k32x:
      return dexInstr_getVRegA_32x(code_ptr);
    case k35c:
      return dexInstr_getVRegA_35c(code_ptr);
    case k3rc:
      return dexInstr_getVRegA_3rc(code_ptr);
    case k45cc:
      return dexInstr_getVRegA_45cc(code_ptr);
    case k4rcc:
      return dexInstr_getVRegA_4rcc(code_ptr);
    case k51l:
      return dexInstr_getVRegA_51l(code_ptr);
    default:
      LOGMSG(l_FATAL, "Tried to access vA of instruction '%s' which has no A operand.",
             dexInst_getOpcodeStr(code_ptr));
      exitWrapper(EXIT_FAILURE);
      return 0;  // Silence "-Wreturn-type"
  }
}

s1 dexInstr_getVRegA_10t(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k10t);
  return (s1)InstAA(code_ptr);
}

u1 dexInstr_getVRegA_10x(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k10x);
  return InstAA(code_ptr);
}

u1 dexInstr_getVRegA_11n(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k11n);
  return InstA(code_ptr);
}

u1 dexInstr_getVRegA_11x(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k11x);
  return InstAA(code_ptr);
}

u1 dexInstr_getVRegA_12x(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k12x);
  return InstA(code_ptr);
}

s2 dexInstr_getVRegA_20t(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k20t);
  return (s2)code_ptr[1];
}

u1 dexInstr_getVRegA_21c(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k21c);
  return InstAA(code_ptr);
}

u1 dexInstr_getVRegA_21h(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k21h);
  return InstAA(code_ptr);
}

u1 dexInstr_getVRegA_21s(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k21s);
  return InstAA(code_ptr);
}

u1 dexInstr_getVRegA_21t(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k21t);
  return InstAA(code_ptr);
}

u1 dexInstr_getVRegA_22b(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k22b);
  return InstAA(code_ptr);
}

u1 dexInstr_getVRegA_22c(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k22c);
  return InstA(code_ptr);
}

u1 dexInstr_getVRegA_22s(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k22s);
  return InstA(code_ptr);
}

u1 dexInstr_getVRegA_22t(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k22t);
  return InstA(code_ptr);
}

u1 dexInstr_getVRegA_22x(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k22x);
  return InstAA(code_ptr);
}

u1 dexInstr_getVRegA_23x(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k23x);
  return InstAA(code_ptr);
}

s4 dexInstr_getVRegA_30t(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k30t);
  return (s4)(code_ptr[1] | ((u4)code_ptr[2] << 16));
}

u1 dexInstr_getVRegA_31c(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k31c);
  return InstAA(code_ptr);
}

u1 dexInstr_getVRegA_31i(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k31i);
  return InstAA(code_ptr);
}

u1 dexInstr_getVRegA_31t(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k31t);
  return InstAA(code_ptr);
}

u2 dexInstr_getVRegA_32x(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k32x);
  return code_ptr[1];
}

u1 dexInstr_getVRegA_35c(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k35c);
  return InstB(code_ptr);  // This is labeled A in the spec.
}

u1 dexInstr_getVRegA_3rc(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k3rc);
  return InstAA(code_ptr);
}

u1 dexInstr_getVRegA_51l(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k51l);
  return InstAA(code_ptr);
}

u1 dexInstr_getVRegA_45cc(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k45cc);
  return InstB(code_ptr);  // This is labeled A in the spec.
}

u1 dexInstr_getVRegA_4rcc(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k4rcc);
  return InstAA(code_ptr);
}

bool dexInstr_hasVRegB(u2 *code_ptr) {
  switch (kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format) {
    case k11n:
      return true;
    case k12x:
      return true;
    case k21c:
      return true;
    case k21h:
      return true;
    case k21s:
      return true;
    case k21t:
      return true;
    case k22b:
      return true;
    case k22c:
      return true;
    case k22s:
      return true;
    case k22t:
      return true;
    case k22x:
      return true;
    case k23x:
      return true;
    case k31c:
      return true;
    case k31i:
      return true;
    case k31t:
      return true;
    case k32x:
      return true;
    case k35c:
      return true;
    case k3rc:
      return true;
    case k45cc:
      return true;
    case k4rcc:
      return true;
    case k51l:
      return true;
    default:
      return false;
  }
}

s4 dexInstr_getVRegB(u2 *code_ptr) {
  switch (kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format) {
    case k11n:
      return dexInstr_getVRegB_11n(code_ptr);
    case k12x:
      return dexInstr_getVRegB_12x(code_ptr);
    case k21c:
      return dexInstr_getVRegB_21c(code_ptr);
    case k21h:
      return dexInstr_getVRegB_21h(code_ptr);
    case k21s:
      return dexInstr_getVRegB_21s(code_ptr);
    case k21t:
      return dexInstr_getVRegB_21t(code_ptr);
    case k22b:
      return dexInstr_getVRegB_22b(code_ptr);
    case k22c:
      return dexInstr_getVRegB_22c(code_ptr);
    case k22s:
      return dexInstr_getVRegB_22s(code_ptr);
    case k22t:
      return dexInstr_getVRegB_22t(code_ptr);
    case k22x:
      return dexInstr_getVRegB_22x(code_ptr);
    case k23x:
      return dexInstr_getVRegB_23x(code_ptr);
    case k31c:
      return dexInstr_getVRegB_31c(code_ptr);
    case k31i:
      return dexInstr_getVRegB_31i(code_ptr);
    case k31t:
      return dexInstr_getVRegB_31t(code_ptr);
    case k32x:
      return dexInstr_getVRegB_32x(code_ptr);
    case k35c:
      return dexInstr_getVRegB_35c(code_ptr);
    case k3rc:
      return dexInstr_getVRegB_3rc(code_ptr);
    case k45cc:
      return dexInstr_getVRegB_45cc(code_ptr);
    case k4rcc:
      return dexInstr_getVRegB_4rcc(code_ptr);
    case k51l:
      return dexInstr_getVRegB_51l(code_ptr);
    default:
      LOGMSG(l_FATAL, "Tried to access vB of instruction '%s' which has no B operand.",
             dexInst_getOpcodeStr(code_ptr));
      exitWrapper(EXIT_FAILURE);
      return 0;  // Silence "-Wreturn-type"
  }
}

u8 dexInstr_getWideVRegB(u2 *code_ptr) { return dexInstr_getVRegB_51l(code_ptr); }

s1 dexInstr_getVRegB_11n(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k11n);
  return (InstB(code_ptr) << 28) >> 28;
}

u1 dexInstr_getVRegB_12x(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k12x);
  return InstB(code_ptr);
}

u2 dexInstr_getVRegB_21c(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k21c);
  return code_ptr[1];
}

u2 dexInstr_getVRegB_21h(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k21h);
  return code_ptr[1];
}

s2 dexInstr_getVRegB_21s(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k21s);
  return (s2)(code_ptr[1]);
}

s2 dexInstr_getVRegB_21t(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k21t);
  return (s2)(code_ptr[1]);
}

u1 dexInstr_getVRegB_22b(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k22b);
  return (u1)(code_ptr[1] & 0xff);
}

u1 dexInstr_getVRegB_22c(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k22c);
  return InstB(code_ptr);
}

u1 dexInstr_getVRegB_22s(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k22s);
  return InstB(code_ptr);
}

u1 dexInstr_getVRegB_22t(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k22t);
  return InstB(code_ptr);
}

u2 dexInstr_getVRegB_22x(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k22x);
  return code_ptr[1];
}

u1 dexInstr_getVRegB_23x(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k23x);
  return (u1)(code_ptr[1] & 0xff);
}

u4 dexInstr_getVRegB_31c(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k31c);
  return (code_ptr[1] | ((u4)code_ptr[2] << 16));
}

s4 dexInstr_getVRegB_31i(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k31i);
  return (s4)(code_ptr[1] | ((u4)code_ptr[2] << 16));
}

s4 dexInstr_getVRegB_31t(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k31t);
  return (s4)(code_ptr[1] | ((u4)code_ptr[2] << 16));
}

u2 dexInstr_getVRegB_32x(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k32x);
  return code_ptr[2];
}

u2 dexInstr_getVRegB_35c(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k35c);
  return code_ptr[1];
}

u2 dexInstr_getVRegB_3rc(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k3rc);
  return code_ptr[1];
}

u2 dexInstr_getVRegB_45cc(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k45cc);
  return code_ptr[1];
}

u2 dexInstr_getVRegB_4rcc(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k4rcc);
  return code_ptr[1];
}

u8 dexInstr_getVRegB_51l(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k51l);
  u8 vB_wide =
      (code_ptr[1] | ((u4)code_ptr[2] << 16)) | ((u8)(code_ptr[3] | ((u4)code_ptr[4] << 16)) << 32);
  return vB_wide;
}

bool dexInstr_hasVRegC(u2 *code_ptr) {
  switch (kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format) {
    case k22b:
      return true;
    case k22c:
      return true;
    case k22s:
      return true;
    case k22t:
      return true;
    case k23x:
      return true;
    case k35c:
      return true;
    case k3rc:
      return true;
    case k45cc:
      return true;
    case k4rcc:
      return true;
    default:
      return false;
  }
}

s4 dexInstr_getVRegC(u2 *code_ptr) {
  switch (kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format) {
    case k22b:
      return dexInstr_getVRegC_22b(code_ptr);
    case k22c:
      return dexInstr_getVRegC_22c(code_ptr);
    case k22s:
      return dexInstr_getVRegC_22s(code_ptr);
    case k22t:
      return dexInstr_getVRegC_22t(code_ptr);
    case k23x:
      return dexInstr_getVRegC_23x(code_ptr);
    case k35c:
      return dexInstr_getVRegC_35c(code_ptr);
    case k3rc:
      return dexInstr_getVRegC_3rc(code_ptr);
    case k45cc:
      return dexInstr_getVRegC_45cc(code_ptr);
    case k4rcc:
      return dexInstr_getVRegC_4rcc(code_ptr);
    default:
      LOGMSG(l_FATAL, "Tried to access vC of instruction '%s' which has no C operand.",
             dexInst_getOpcodeStr(code_ptr));
      exitWrapper(EXIT_FAILURE);
      return 0;  // Silence "-Wreturn-type"
  }
}

s1 dexInstr_getVRegC_22b(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k22b);
  return (s1)(code_ptr[1] >> 8);
}

u2 dexInstr_getVRegC_22c(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k22c);
  return code_ptr[1];
}

s2 dexInstr_getVRegC_22s(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k22s);
  return (s2)(code_ptr[1]);
}

s2 dexInstr_getVRegC_22t(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k22t);
  return (s2)(code_ptr[1]);
}

u1 dexInstr_getVRegC_23x(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k23x);
  return (u1)(code_ptr[1] >> 8);
}

u1 dexInstr_getVRegC_35c(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k35c);
  return (u1)(code_ptr[2] & 0x0f);
}

u2 dexInstr_getVRegC_3rc(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k3rc);
  return code_ptr[2];
}

u1 dexInstr_getVRegC_45cc(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k45cc);
  return (u1)(code_ptr[2] & 0x0f);
}

u2 dexInstr_getVRegC_4rcc(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k4rcc);
  return code_ptr[2];
}

bool dexInstr_hasVRegH(u2 *code_ptr) {
  switch (kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format) {
    case k45cc:
      return true;
    case k4rcc:
      return true;
    default:
      return false;
  }
}

s4 dexInstr_getVRegH(u2 *code_ptr) {
  switch (kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format) {
    case k45cc:
      return dexInstr_getVRegH_45cc(code_ptr);
    case k4rcc:
      return dexInstr_getVRegH_4rcc(code_ptr);
    default:
      LOGMSG(l_FATAL, "Tried to access vH of instruction '%s' which has no H operand.",
             dexInst_getOpcodeStr(code_ptr));
      exitWrapper(EXIT_FAILURE);
      return 0;  // Silence "-Wreturn-type"
  }
}

bool dexInstr_HasVarArgs(u2 *code_ptr) {
  return (kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format == k35c) ||
         (kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format == k45cc);
}

void dexInstr_getVarArgs(u2 *code_ptr, u4 arg[kMaxVarArgRegs]) {
  CHECK(dexInstr_HasVarArgs(code_ptr));

  // Note that the fields mentioned in the spec don't appear in
  // their "usual" positions here compared to most formats. This
  // was done so that the field names for the argument count and
  // reference index match between this format and the corresponding
  // range formats (3rc and friends).
  //
  // Bottom line: The argument count is always in vA, and the
  // method constant (or equivalent) is always in vB.
  u2 regList = code_ptr[2];
  u1 count = InstB(code_ptr);  // This is labeled A in the spec.
  if (count > 5U) {
    LOGMSG(l_FATAL, "Invalid arg count in 35c (%" PRIx8 ")", count);
  }

  // Copy the argument registers into the arg[] array, and
  // also copy the first argument (if any) into vC. (The
  // DecodedInstruction structure doesn't have separate
  // fields for {vD, vE, vF, vG}, so there's no need to make
  // copies of those.) Note that cases 5..2 fall through.
  switch (count) {
    case 5:
      arg[4] = InstA(code_ptr);
    /* fall through */
    case 4:
      arg[3] = (regList >> 12) & 0x0f;
    /* fall through */
    case 3:
      arg[2] = (regList >> 8) & 0x0f;
    /* fall through */
    case 2:
      arg[1] = (regList >> 4) & 0x0f;
    /* fall through */
    case 1:
      arg[0] = regList & 0x0f;
      break;
    default:  // case 0
      break;  // Valid, but no need to do anything.
  }
}

u2 dexInstr_getVRegH_45cc(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k45cc);
  return code_ptr[3];
}

u2 dexInstr_getVRegH_4rcc(u2 *code_ptr) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k4rcc);
  return code_ptr[3];
}

void dexInstr_SetVRegA_10x(u2 *code_ptr, u1 val) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k10x);
  code_ptr[0] = (val << 8) | (code_ptr[0] & 0x00ff);
}

void dexInstr_SetVRegB_3rc(u2 *code_ptr, u2 val) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k3rc);
  code_ptr[1] = val;
}

void dexInstr_SetVRegB_35c(u2 *code_ptr, u2 val) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k35c);
  code_ptr[1] = val;
}

void dexInstr_SetVRegC_22c(u2 *code_ptr, u2 val) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k22c);
  code_ptr[1] = val;
}

void dexInstr_SetVRegA_21c(u2 *code_ptr, u1 val) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k21c);
  code_ptr[0] = (val << 8) | (code_ptr[0] & 0x00ff);
}

void dexInstr_SetVRegB_21c(u2 *code_ptr, u2 val) {
  CHECK_EQ(kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].format, k21c);
  code_ptr[1] = val;
}

bool dexInstr_isBranch(u2 *code_ptr) {
  return (kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].flags & kBranch) != 0;
}

bool dexInstr_isUnconditional(u2 *code_ptr) {
  return (kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].flags & kUnconditional) != 0;
}

bool dexInstr_isQuickened(u2 *code_ptr) {
  return (kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].index_type == kIndexFieldOffset) ||
         (kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].index_type == kIndexVtableOffset);
}

bool dexInstr_isSwitch(u2 *code_ptr) {
  return (kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].flags & kSwitch) != 0;
}

bool dexInstr_isThrow(u2 *code_ptr) {
  return (kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].flags & kThrow) != 0;
}

bool dexInstr_isReturn(u2 *code_ptr) {
  return (kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].flags & kReturn) != 0;
}

bool dexInstr_isBasicBlockEnd(u2 *code_ptr) {
  return dexInstr_isBranch(code_ptr) || dexInstr_isReturn(code_ptr) ||
         dexInstr_getOpcode(code_ptr) == THROW;
}

bool dexInstr_isInvoke(u2 *code_ptr) {
  return (kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].flags & kInvoke) != 0;
}

u4 dexInstr_SizeInCodeUnits(u2 *code_ptr) {
  s1 result = kInstructionDescriptors[dexInstr_getOpcode(code_ptr)].size_in_code_units;
  if (result < 0) {
    return SizeInCodeUnitsComplexOpcode(code_ptr);
  } else {
    return (u4)result;
  }
}
