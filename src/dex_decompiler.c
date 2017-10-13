#include "dex_decompiler.h"
#include "utils.h"

static const uint8_t *quickening_info_ptr;
static const uint8_t *quickening_info_end;

static uint16_t *code_ptr;
static uint16_t *code_end;
static uint32_t dex_pc;
static uint32_t cur_code_off;

static void initCodeIterator(uint16_t *pCode,
                             uint32_t codeSize,
                             uint32_t startCodeOff) {
  code_ptr = pCode;
  code_end = pCode + codeSize;
  dex_pc = 0;
  cur_code_off = startCodeOff;
}

static bool isCodeIteratorDone() { return code_ptr >= code_end; }

static void codeIteratorAdvance() {
  uint32_t instruction_size = dexInstr_SizeInCodeUnits(code_ptr);
  code_ptr += instruction_size;
  dex_pc += instruction_size;
  cur_code_off += instruction_size * sizeof(uint16_t);
}

static uint16_t GetIndexAt(uint32_t dex_pc) {
  // Note that as a side effect, dex_readULeb128 update the given pointer
  // to the new position in the buffer.
  CHECK_LT(quickening_info_ptr, quickening_info_end);
  uint32_t quickened_pc = dex_readULeb128(&quickening_info_ptr);
  CHECK_LT(quickening_info_ptr, quickening_info_end);
  uint16_t index = dex_readULeb128(&quickening_info_ptr);
  CHECK_LE(quickening_info_ptr, quickening_info_end);
  CHECK_EQ(quickened_pc, dex_pc);
  return index;
}

static void DecompileNop(uint16_t *insns, uint32_t dex_pc) {
  if (quickening_info_ptr == quickening_info_end) {
    return;
  }
  const uint8_t *temporary_pointer = quickening_info_ptr;
  uint32_t quickened_pc = dex_readULeb128(&temporary_pointer);
  if (quickened_pc != dex_pc) {
    LOGMSG(l_FATAL, "Fatal error when decompiling NOP instruction");
    return;
  }
  uint16_t reference_index = GetIndexAt(dex_pc);
  uint16_t type_index = GetIndexAt(dex_pc);
  dexInstr_SetOpcode(insns, CHECK_CAST);
  dexInstr_SetVRegA_21c(insns, reference_index);
  dexInstr_SetVRegB_21c(insns, type_index);
}

static void DecompileInstanceFieldAccess(uint16_t *insns,
                                         uint32_t dex_pc,
                                         Code new_opcode) {
  uint16_t index = GetIndexAt(dex_pc);
  dexInstr_SetOpcode(insns, new_opcode);
  dexInstr_SetVRegC_22c(insns, index);
}

static void DecompileInvokeVirtual(uint16_t *insns,
                                   uint32_t dex_pc,
                                   Code new_opcode,
                                   bool is_range) {
  uint16_t index = GetIndexAt(dex_pc);
  dexInstr_SetOpcode(insns, new_opcode);
  if (is_range) {
    dexInstr_SetVRegB_3rc(insns, index);
  } else {
    dexInstr_SetVRegB_35c(insns, index);
  }
}

bool dexDecompiler_decompile(dexCode *pDexCode,
                             uint32_t startCodeOff,
                             const uint8_t *quickening_info,
                             uint32_t quickening_size,
                             bool decompile_return_instruction) {
  if (quickening_size == 0 && !decompile_return_instruction) {
    return true;
  }

  quickening_info_ptr = quickening_info;
  quickening_info_end = quickening_info + quickening_size;
  LOGMSG(l_VDEBUG, "\t\t\tquickening_size=%" PRIx32, quickening_size);
  initCodeIterator(pDexCode->insns, pDexCode->insns_size, startCodeOff);

  while (isCodeIteratorDone() == false) {
    LOGMSG(l_VDEBUG, "\t\t\t  %" PRIx32 ": %s", cur_code_off,
           dexInst_getOpcodeStr(code_ptr));
    switch (dexInstr_getOpcode(code_ptr)) {
      case RETURN_VOID_NO_BARRIER:
        if (decompile_return_instruction) {
          dexInstr_SetOpcode(code_ptr, RETURN_VOID);
        }
        break;
      case NOP:
        DecompileNop(code_ptr, dex_pc);
        break;
      case IGET_QUICK:
        DecompileInstanceFieldAccess(code_ptr, dex_pc, IGET);
        break;
      case IGET_WIDE_QUICK:
        DecompileInstanceFieldAccess(code_ptr, dex_pc, IGET_WIDE);
        break;
      case IGET_OBJECT_QUICK:
        DecompileInstanceFieldAccess(code_ptr, dex_pc, IGET_OBJECT);
        break;
      case IGET_BOOLEAN_QUICK:
        DecompileInstanceFieldAccess(code_ptr, dex_pc, IGET_BOOLEAN);
        break;
      case IGET_BYTE_QUICK:
        DecompileInstanceFieldAccess(code_ptr, dex_pc, IGET_BYTE);
        break;
      case IGET_CHAR_QUICK:
        DecompileInstanceFieldAccess(code_ptr, dex_pc, IGET_CHAR);
        break;
      case IGET_SHORT_QUICK:
        DecompileInstanceFieldAccess(code_ptr, dex_pc, IGET_SHORT);
        break;
      case IPUT_QUICK:
        DecompileInstanceFieldAccess(code_ptr, dex_pc, IPUT);
        break;
      case IPUT_BOOLEAN_QUICK:
        DecompileInstanceFieldAccess(code_ptr, dex_pc, IPUT_BOOLEAN);
        break;
      case IPUT_BYTE_QUICK:
        DecompileInstanceFieldAccess(code_ptr, dex_pc, IPUT_BYTE);
        break;
      case IPUT_CHAR_QUICK:
        DecompileInstanceFieldAccess(code_ptr, dex_pc, IPUT_CHAR);
        break;
      case IPUT_SHORT_QUICK:
        DecompileInstanceFieldAccess(code_ptr, dex_pc, IPUT_SHORT);
        break;
      case IPUT_WIDE_QUICK:
        DecompileInstanceFieldAccess(code_ptr, dex_pc, IPUT_WIDE);
        break;
      case IPUT_OBJECT_QUICK:
        DecompileInstanceFieldAccess(code_ptr, dex_pc, IPUT_OBJECT);
        break;
      case INVOKE_VIRTUAL_QUICK:
        DecompileInvokeVirtual(code_ptr, dex_pc, INVOKE_VIRTUAL, false);
        break;
      case INVOKE_VIRTUAL_RANGE_QUICK:
        DecompileInvokeVirtual(code_ptr, dex_pc, INVOKE_VIRTUAL_RANGE, true);
        break;
      default:
        break;
    }

    codeIteratorAdvance();
  }

  if (quickening_info_ptr != quickening_info_end) {
    if (quickening_info_ptr == quickening_info_end) {
      LOGMSG(l_ERROR,
             "Failed to use any value in quickening info, potentially"
             " due to duplicate methods.");
    } else {
      LOGMSG(l_ERROR,
             "Failed to use all values in quickening info, '%zx' items not "
             "processed",
             quickening_info_end - quickening_info_ptr);
      return false;
    }
  }

  return true;
}
