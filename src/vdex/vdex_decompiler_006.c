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

#include "vdex_decompiler_006.h"

#include "../utils.h"

static const u1 *quickening_info_ptr;
static const u1 *quickening_info_end;

static u2 *code_ptr;
static u2 *code_end;
static u4 dex_pc;
static u4 cur_code_off;

static void initCodeIterator(u2 *pCode, u4 codeSize, u4 startCodeOff) {
  code_ptr = pCode;
  code_end = pCode + codeSize;
  dex_pc = 0;
  cur_code_off = startCodeOff;
}

static bool isCodeIteratorDone() { return code_ptr >= code_end; }

static void codeIteratorAdvance() {
  u4 instruction_size = dexInstr_SizeInCodeUnits(code_ptr);
  code_ptr += instruction_size;
  dex_pc += instruction_size;
  cur_code_off += instruction_size * sizeof(u2);
}

static u2 GetIndexAt(u4 dex_pc) {
  // Note that as a side effect, dex_readULeb128 update the given pointer
  // to the new position in the buffer.
  CHECK_LT(quickening_info_ptr, quickening_info_end);
  u4 quickened_pc = dex_readULeb128(&quickening_info_ptr);
  CHECK_LT(quickening_info_ptr, quickening_info_end);
  u2 index = dex_readULeb128(&quickening_info_ptr);
  CHECK_LE(quickening_info_ptr, quickening_info_end);
  CHECK_EQ(quickened_pc, dex_pc);
  return index;
}

static bool DecompileNop(u2 *insns, u4 dex_pc) {
  if (quickening_info_ptr == quickening_info_end) {
    return false;
  }
  const u1 *temporary_pointer = quickening_info_ptr;
  u4 quickened_pc = dex_readULeb128(&temporary_pointer);
  if (quickened_pc != dex_pc) {
    return false;
  }
  u2 reference_index = GetIndexAt(dex_pc);
  u2 type_index = GetIndexAt(dex_pc);
  dexInstr_SetOpcode(insns, CHECK_CAST);
  dexInstr_SetVRegA_21c(insns, reference_index);
  dexInstr_SetVRegB_21c(insns, type_index);

  return true;
}

static void DecompileInstanceFieldAccess(u2 *insns, u4 dex_pc, Code new_opcode) {
  u2 index = GetIndexAt(dex_pc);
  dexInstr_SetOpcode(insns, new_opcode);
  dexInstr_SetVRegC_22c(insns, index);
}

static void DecompileInvokeVirtual(u2 *insns, u4 dex_pc, Code new_opcode, bool is_range) {
  u2 index = GetIndexAt(dex_pc);
  dexInstr_SetOpcode(insns, new_opcode);
  if (is_range) {
    dexInstr_SetVRegB_3rc(insns, index);
  } else {
    dexInstr_SetVRegB_35c(insns, index);
  }
}

bool vdex_decompiler_006_decompile(const u1 *dexFileBuf,
                                   dexMethod *pDexMethod,
                                   const u1 *quickening_info,
                                   u4 quickening_size,
                                   bool decompile_return_instruction) {
  if (quickening_size == 0 && !decompile_return_instruction) {
    return true;
  }

  dexCode *pDexCode = (dexCode *)(dexFileBuf + pDexMethod->codeOff);
  u4 startCodeOff = dex_getFirstInstrOff(dexFileBuf, pDexMethod);

  quickening_info_ptr = quickening_info;
  quickening_info_end = quickening_info + quickening_size;
  log_dis("    quickening_size=%" PRIx32 " (%" PRIu32 ")\n", quickening_size, quickening_size);
  initCodeIterator(pDexCode->insns, pDexCode->insnsSize, startCodeOff);

  while (isCodeIteratorDone() == false) {
    bool hasCodeChange = true;
    dex_dumpInstruction(dexFileBuf, code_ptr, cur_code_off, dex_pc, false);
    switch (dexInstr_getOpcode(code_ptr)) {
      case RETURN_VOID_NO_BARRIER:
        if (decompile_return_instruction) {
          dexInstr_SetOpcode(code_ptr, RETURN_VOID);
        }
        break;
      case NOP:
        hasCodeChange = DecompileNop(code_ptr, dex_pc);
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
        hasCodeChange = false;
        break;
    }

    if (hasCodeChange) {
      dex_dumpInstruction(dexFileBuf, code_ptr, cur_code_off, dex_pc, true);
    }
    codeIteratorAdvance();
  }

  if (quickening_info_ptr != quickening_info_end) {
    if (quickening_info_ptr == quickening_info_end) {
      LOGMSG(l_ERROR,
             "Failed to use any value in quickening info, potentially due to duplicate methods.");
    } else {
      LOGMSG(l_ERROR, "Failed to use all values in quickening info, '%zx' items not processed",
             quickening_info_end - quickening_info_ptr);
      return false;
    }
  }

  return true;
}

void vdex_decompiler_006_walk(const u1 *dexFileBuf, dexMethod *pDexMethod) {
  dexCode *pDexCode = (dexCode *)(dexFileBuf + pDexMethod->codeOff);
  u4 startCodeOff = dex_getFirstInstrOff(dexFileBuf, pDexMethod);
  initCodeIterator(pDexCode->insns, pDexCode->insnsSize, startCodeOff);
  while (isCodeIteratorDone() == false) {
    dex_dumpInstruction(dexFileBuf, code_ptr, cur_code_off, dex_pc, false);
    codeIteratorAdvance();
  }
}
