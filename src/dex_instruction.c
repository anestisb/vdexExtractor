#include "dex_instruction.h"
#include "log.h"

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

uint32_t dexInstr_SizeInCodeUnits(uint16_t *code_ptr) {
  int result = kInstructionSizeInCodeUnits[dexInstr_getOpcode(code_ptr)];
  if (result < 0) {
    return SizeInCodeUnitsComplexOpcode(code_ptr);
  } else {
    return result;
  }
}
