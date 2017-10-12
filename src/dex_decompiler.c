#include "dex_decompiler.h"
#include "utils.h"

static const uint8_t *quickening_info_ptr;
static const uint8_t *quickening_info_end;

static uint16_t *code_ptr;
static uint16_t *code_end;
static uint32_t dex_pc;

static void initCodeIterator(uint16_t *pCode, uint32_t codeSize) {
  code_ptr = pCode;
  code_end = pCode + codeSize;
  dex_pc = 0;
}

static bool isCodeIteratorDone() { return code_ptr >= code_end; }

static void codeIteratorAdvance() {
  uint32_t instruction_size = dexInstr_SizeInCodeUnits(code_ptr);
  code_ptr += instruction_size;
  dex_pc += instruction_size;
}

bool dexDecompiler_decompile(dexCode *pDexCode,
                             const uint8_t *quickening_data_start,
                             uint32_t quickening_data_size,
                             bool decompile_return_instruction) {
  if (quickening_data_size == 0 && !decompile_return_instruction) {
    return true;
  }

  quickening_info_ptr = quickening_data_start;
  quickening_info_end = quickening_data_start + quickening_data_size;
  initCodeIterator(pDexCode->insns, pDexCode->insns_size);

  while (isCodeIteratorDone() == false) {
    switch (dexInstr_getOpcode(code_ptr)) {
      case RETURN_VOID_NO_BARRIER:
        LOGMSG(l_DEBUG, "RETURN_VOID_NO_BARRIER");
      case NOP:
        LOGMSG(l_DEBUG, "NOP");
      case IGET_QUICK:
        LOGMSG(l_DEBUG, "IGET_QUICK");
      case IGET_WIDE_QUICK:
        LOGMSG(l_DEBUG, "IGET_WIDE_QUICK");
      case IGET_OBJECT_QUICK:
        LOGMSG(l_DEBUG, "IGET_OBJECT_QUICK");
      case IGET_BOOLEAN_QUICK:
        LOGMSG(l_DEBUG, "IGET_BOOLEAN_QUICK");
      case IGET_BYTE_QUICK:
        LOGMSG(l_DEBUG, "IGET_BYTE_QUICK");
      case IGET_CHAR_QUICK:
        LOGMSG(l_DEBUG, "IGET_CHAR_QUICK");
      case IGET_SHORT_QUICK:
        LOGMSG(l_DEBUG, "IGET_SHORT_QUICK");
      case IPUT_QUICK:
        LOGMSG(l_DEBUG, "IPUT_QUICK");
      case IPUT_BOOLEAN_QUICK:
        LOGMSG(l_DEBUG, "IPUT_BOOLEAN_QUICK");
      case IPUT_BYTE_QUICK:
        LOGMSG(l_DEBUG, "IPUT_BYTE_QUICK");
      case IPUT_CHAR_QUICK:
        LOGMSG(l_DEBUG, "IPUT_CHAR_QUICK");
      case IPUT_SHORT_QUICK:
        LOGMSG(l_DEBUG, "IPUT_SHORT_QUICK");
      case IPUT_WIDE_QUICK:
        LOGMSG(l_DEBUG, "IPUT_WIDE_QUICK");
      case IPUT_OBJECT_QUICK:
        LOGMSG(l_DEBUG, "IPUT_OBJECT_QUICK");
      case INVOKE_VIRTUAL_QUICK:
        LOGMSG(l_DEBUG, "INVOKE_VIRTUAL_QUICK");
      case INVOKE_VIRTUAL_RANGE_QUICK:
        LOGMSG(l_DEBUG, "INVOKE_VIRTUAL_RANGE_QUICK");
      default:
        break;
    }

    codeIteratorAdvance();
  }

  if (quickening_info_ptr != quickening_info_end) {
    if (quickening_data_start == quickening_info_ptr) {
      LOGMSG(l_ERROR,
             "Failed to use any value in quickening info, potentially"
             " due to duplicate methods.");
    } else {
      LOGMSG(l_ERROR, "Failed to use all values in quickening info.");
      return false;
    }
  }

  return true;
}
