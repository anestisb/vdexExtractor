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

Code dexInstr_getOpcode(uint16_t *code_ptr) {
  uint16_t inst_data = code_ptr[0];
  return (inst_data & 0xFF);
}

const char *dexInst_getOpcodeStr(uint16_t *code_ptr) {
  return kInstructionNames[dexInstr_getOpcode(code_ptr)];
}

void dexInstr_SetOpcode(uint16_t *code_ptr, Code opcode) {
  CHECK_LT(opcode, 256u);
  code_ptr[0] = (code_ptr[0] & 0xff00) | opcode;
}

void dexInstr_SetVRegA_10x(uint16_t *code_ptr, uint8_t val) {
  CHECK(kInstructionFormats[dexInstr_getOpcode(code_ptr)] == k10x);
  code_ptr[0] = (val << 8) | (code_ptr[0] & 0x00ff);
}

void dexInstr_SetVRegB_3rc(uint16_t *code_ptr, uint16_t val) {
  CHECK(kInstructionFormats[dexInstr_getOpcode(code_ptr)] == k3rc);
  code_ptr[1] = val;
}

void dexInstr_SetVRegB_35c(uint16_t *code_ptr, uint16_t val) {
  CHECK(kInstructionFormats[dexInstr_getOpcode(code_ptr)] == k35c);
  code_ptr[1] = val;
}

void dexInstr_SetVRegC_22c(uint16_t *code_ptr, uint16_t val) {
  CHECK(kInstructionFormats[dexInstr_getOpcode(code_ptr)] == k22c);
  code_ptr[1] = val;
}

void dexInstr_SetVRegA_21c(uint16_t *code_ptr, uint8_t val) {
  CHECK(kInstructionFormats[dexInstr_getOpcode(code_ptr)] == k21c);
  code_ptr[0] = (val << 8) | (code_ptr[0] & 0x00ff);
}

void dexInstr_SetVRegB_21c(uint16_t *code_ptr, uint16_t val) {
  CHECK(kInstructionFormats[dexInstr_getOpcode(code_ptr)] == k21c);
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
