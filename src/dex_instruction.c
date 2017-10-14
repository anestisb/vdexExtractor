/*

   vdexExtractor
   -----------------------------------------

   Anestis Bechtsoudis <anestis@census-labs.com>
   Copyright 2017 by CENSUS S.A. All Rights Reserved.

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

static uint32_t SizeInCodeUnitsComplexOpcode(uint16_t *code_ptr) {
  // Handle special NOP encoded variable length sequences.
  switch (*code_ptr) {
    case kPackedSwitchSignature:
      return (4 + code_ptr[1] * 2);
    case kSparseSwitchSignature:
      return (2 + code_ptr[1] * 4);
    case kArrayDataSignature: {
      uint16_t element_size = code_ptr[1];
      uint32_t length = code_ptr[2] | (((uint32_t)code_ptr[3]) << 16);
      // The plus 1 is to round up for odd size and width.
      return (4 + (element_size * length + 1) / 2);
    }
    default:
      if ((*code_ptr & 0xFF) == 0) {
        return 1;  // NOP.
      } else {
        LOGMSG(l_FATAL, "Error when decoding complex opcode");
        exit(EXIT_FAILURE);
      }
  }
}

static uint8_t InstAA(uint16_t *code_ptr, uint16_t inst_data) {
  CHECK_EQ(inst_data, code_ptr[0]);
  return inst_data >> 8;
}

static uint8_t InstA(uint16_t *code_ptr, uint16_t inst_data) {
  CHECK_EQ(inst_data, code_ptr[0]);
  return (inst_data >> 8) & 0x0f;
}

static uint8_t InstB(uint16_t *code_ptr, uint16_t inst_data) {
  CHECK_EQ(inst_data, code_ptr[0]);
  return inst_data >> 12;
}

Code dexInstr_getOpcode(uint16_t *code_ptr) { return (code_ptr[0] & 0xFF); }

const char *dexInst_getOpcodeStr(uint16_t *code_ptr) {
  return kInstructionNames[dexInstr_getOpcode(code_ptr)];
}

void dexInstr_SetOpcode(uint16_t *code_ptr, Code opcode) {
  CHECK_LT(opcode, 256u);
  code_ptr[0] = (code_ptr[0] & 0xff00) | opcode;
}

bool dexInstr_hasVRegA(uint16_t *code_ptr) {
  switch (kInstructionFormats[dexInstr_getOpcode(code_ptr)]) {
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

int32_t dexInstr_getVRegA(uint16_t *code_ptr) {
  switch (kInstructionFormats[dexInstr_getOpcode(code_ptr)]) {
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
      exit(EXIT_FAILURE);
  }
}

int8_t dexInstr_getVRegA_10t(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k10t);
  return (int8_t)InstAA(code_ptr, code_ptr[0]);
}

uint8_t dexInstr_getVRegA_10x(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k10x);
  return InstAA(code_ptr, code_ptr[0]);
}

uint8_t dexInstr_getVRegA_11n(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k11n);
  return InstA(code_ptr, code_ptr[0]);
}

uint8_t dexInstr_getVRegA_11x(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k11x);
  return InstAA(code_ptr, code_ptr[0]);
}

uint8_t dexInstr_getVRegA_12x(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k12x);
  return InstA(code_ptr, code_ptr[0]);
}

int16_t dexInstr_getVRegA_20t(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k20t);
  return (int16_t)code_ptr[1];
}

uint8_t dexInstr_getVRegA_21c(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k21c);
  return InstAA(code_ptr, code_ptr[0]);
}

uint8_t dexInstr_getVRegA_21h(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k21h);
  return InstAA(code_ptr, code_ptr[0]);
}

uint8_t dexInstr_getVRegA_21s(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k21s);
  return InstAA(code_ptr, code_ptr[0]);
}

uint8_t dexInstr_getVRegA_21t(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k21t);
  return InstAA(code_ptr, code_ptr[0]);
}

uint8_t dexInstr_getVRegA_22b(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k22b);
  return InstAA(code_ptr, code_ptr[0]);
}

uint8_t dexInstr_getVRegA_22c(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k22c);
  return InstA(code_ptr, code_ptr[0]);
}

uint8_t dexInstr_getVRegA_22s(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k22s);
  return InstA(code_ptr, code_ptr[0]);
}

uint8_t dexInstr_getVRegA_22t(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k22t);
  return InstA(code_ptr, code_ptr[0]);
}

uint8_t dexInstr_getVRegA_22x(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k22x);
  return InstAA(code_ptr, code_ptr[0]);
}

uint8_t dexInstr_getVRegA_23x(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k23x);
  return InstAA(code_ptr, code_ptr[0]);
}

int32_t dexInstr_getVRegA_30t(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k30t);
  return (int32_t)(code_ptr[1] | ((uint32_t)code_ptr[2] << 16));
}

uint8_t dexInstr_getVRegA_31c(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k31c);
  return InstAA(code_ptr, code_ptr[0]);
}

uint8_t dexInstr_getVRegA_31i(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k31i);
  return InstAA(code_ptr, code_ptr[0]);
}

uint8_t dexInstr_getVRegA_31t(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k31t);
  return InstAA(code_ptr, code_ptr[0]);
}

uint16_t dexInstr_getVRegA_32x(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k32x);
  return code_ptr[1];
}

uint8_t dexInstr_getVRegA_35c(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k35c);
  return InstB(code_ptr, code_ptr[0]);  // This is labeled A in the spec.
}

uint8_t dexInstr_getVRegA_3rc(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k3rc);
  return InstAA(code_ptr, code_ptr[0]);
}

uint8_t dexInstr_getVRegA_51l(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k51l);
  return InstAA(code_ptr, code_ptr[0]);
}

uint8_t dexInstr_getVRegA_45cc(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k45cc);
  return InstB(code_ptr, code_ptr[0]);  // This is labeled A in the spec.
}

uint8_t dexInstr_getVRegA_4rcc(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k4rcc);
  return InstAA(code_ptr, code_ptr[0]);
}

bool dexInstr_hasVRegB(uint16_t *code_ptr) {
  switch (kInstructionFormats[dexInstr_getOpcode(code_ptr)]) {
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

int32_t dexInstr_getVRegB(uint16_t *code_ptr) {
  switch (kInstructionFormats[dexInstr_getOpcode(code_ptr)]) {
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
      exit(EXIT_FAILURE);
  }
}

uint64_t dexInstr_getWideVRegB(uint16_t *code_ptr) { return dexInstr_getVRegB_51l(code_ptr); }

int8_t dexInstr_getVRegB_11n(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k11n);
  return (InstB(code_ptr, code_ptr[0]) << 28) >> 28;
}

uint8_t dexInstr_getVRegB_12x(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k12x);
  return InstB(code_ptr, code_ptr[0]);
}

uint16_t dexInstr_getVRegB_21c(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k21c);
  return code_ptr[1];
}

uint16_t dexInstr_getVRegB_21h(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k21h);
  return code_ptr[1];
}

int16_t dexInstr_getVRegB_21s(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k21s);
  return (int16_t)(code_ptr[1]);
}

int16_t dexInstr_getVRegB_21t(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k21t);
  return (int16_t)(code_ptr[1]);
}

uint8_t dexInstr_getVRegB_22b(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k22b);
  return (uint8_t)(code_ptr[1] & 0xff);
}

uint8_t dexInstr_getVRegB_22c(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k22c);
  return InstB(code_ptr, code_ptr[0]);
}

uint8_t dexInstr_getVRegB_22s(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k22s);
  return InstB(code_ptr, code_ptr[0]);
}

uint8_t dexInstr_getVRegB_22t(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k22t);
  return InstB(code_ptr, code_ptr[0]);
}

uint16_t dexInstr_getVRegB_22x(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k22x);
  return code_ptr[1];
}

uint8_t dexInstr_getVRegB_23x(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k23x);
  return (uint8_t)(code_ptr[1] & 0xff);
}

uint32_t dexInstr_getVRegB_31c(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k31c);
  return (code_ptr[1] | ((uint32_t)code_ptr[2] << 16));
}

int32_t dexInstr_getVRegB_31i(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k31i);
  return (int32_t)(code_ptr[1] | ((uint32_t)code_ptr[2] << 16));
}

int32_t dexInstr_getVRegB_31t(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k31t);
  return (int32_t)(code_ptr[1] | ((uint32_t)code_ptr[2] << 16));
}

uint16_t dexInstr_getVRegB_32x(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k32x);
  return code_ptr[2];
}

uint16_t dexInstr_getVRegB_35c(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k35c);
  return code_ptr[1];
}

uint16_t dexInstr_getVRegB_3rc(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k3rc);
  return code_ptr[1];
}

uint16_t dexInstr_getVRegB_45cc(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k45cc);
  return code_ptr[1];
}

uint16_t dexInstr_getVRegB_4rcc(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k4rcc);
  return code_ptr[1];
}

uint64_t dexInstr_getVRegB_51l(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k51l);
  uint64_t vB_wide = (code_ptr[1] | ((uint32_t)code_ptr[2] << 16)) |
                     ((uint64_t)(code_ptr[3] | ((uint32_t)code_ptr[4] << 16)) << 32);
  return vB_wide;
}

bool dexInstr_hasVRegC(uint16_t *code_ptr) {
  switch (kInstructionFormats[dexInstr_getOpcode(code_ptr)]) {
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

int32_t dexInstr_getVRegC(uint16_t *code_ptr) {
  switch (kInstructionFormats[dexInstr_getOpcode(code_ptr)]) {
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
      exit(EXIT_FAILURE);
  }
}

int8_t dexInstr_getVRegC_22b(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k22b);
  return (int8_t)(code_ptr[1] >> 8);
}

uint16_t dexInstr_getVRegC_22c(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k22c);
  return code_ptr[1];
}

int16_t dexInstr_getVRegC_22s(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k22s);
  return (int16_t)(code_ptr[1]);
}

int16_t dexInstr_getVRegC_22t(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k22t);
  return (int16_t)(code_ptr[1]);
}

uint8_t dexInstr_getVRegC_23x(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k23x);
  return (uint8_t)(code_ptr[1] >> 8);
}

uint8_t dexInstr_getVRegC_35c(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k35c);
  return (uint8_t)(code_ptr[2] & 0x0f);
}

uint16_t dexInstr_getVRegC_3rc(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k3rc);
  return code_ptr[2];
}

uint8_t dexInstr_getVRegC_45cc(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k45cc);
  return (uint8_t)(code_ptr[2] & 0x0f);
}

uint16_t dexInstr_getVRegC_4rcc(uint16_t *code_ptr) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k4rcc);
  return code_ptr[2];
}

void dexInstr_SetVRegA_10x(uint16_t *code_ptr, uint8_t val) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k10x);
  code_ptr[0] = (val << 8) | (code_ptr[0] & 0x00ff);
}

void dexInstr_SetVRegB_3rc(uint16_t *code_ptr, uint16_t val) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k3rc);
  code_ptr[1] = val;
}

void dexInstr_SetVRegB_35c(uint16_t *code_ptr, uint16_t val) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k35c);
  code_ptr[1] = val;
}

void dexInstr_SetVRegC_22c(uint16_t *code_ptr, uint16_t val) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k22c);
  code_ptr[1] = val;
}

void dexInstr_SetVRegA_21c(uint16_t *code_ptr, uint8_t val) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k21c);
  code_ptr[0] = (val << 8) | (code_ptr[0] & 0x00ff);
}

void dexInstr_SetVRegB_21c(uint16_t *code_ptr, uint16_t val) {
  CHECK_EQ(kInstructionFormats[dexInstr_getOpcode(code_ptr)], k21c);
  code_ptr[1] = val;
}

uint32_t dexInstr_SizeInCodeUnits(uint16_t *code_ptr) {
  int result = kInstructionSizeInCodeUnits[dexInstr_getOpcode(code_ptr)];
  if (result < 0) {
    return SizeInCodeUnitsComplexOpcode(code_ptr);
  } else {
    return result;
  }
}
