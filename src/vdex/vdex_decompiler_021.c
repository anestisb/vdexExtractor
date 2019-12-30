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

#include "vdex_decompiler_021.h"

#include "../utils.h"

static const u1 *quicken_info_ptr;
static size_t quicken_info_number_of_indices;
static size_t quicken_index;

static u2 GetData(size_t index) {
  return quicken_info_ptr[index * 2] | ((u2)(quicken_info_ptr[index * 2 + 1]) << 8);
}

static u4 NumberOfIndices(const u1 **data, u4 data_size) {
  return data_size != 0 ? dex_readULeb128(data) : 0u;
}

static u2 *code_ptr;
static u2 *code_end;
static u4 dex_pc;
static u4 cur_code_off;

static void initQuickenInfoTable(const vdex_data_array_t *quickenData) {
  quicken_info_ptr = quickenData->data;
  quicken_index = 0;
  quicken_info_number_of_indices = NumberOfIndices(&quicken_info_ptr, quickenData->size);
}

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

static u2 NextIndex() {
  CHECK_LT(quicken_index, quicken_info_number_of_indices);
  const u2 ret = GetData(quicken_index);
  quicken_index++;
  return ret;
}

static bool DecompileNop(u2 *insns) {
  const u2 reference_index = NextIndex();
  if (reference_index == kDexNoIndex16) {
    // This means it was a normal nop and not a check-cast.
    return false;
  }
  const u2 type_index = NextIndex();
  dexInstr_SetOpcode(insns, CHECK_CAST);
  dexInstr_SetVRegA_21c(insns, reference_index);
  dexInstr_SetVRegB_21c(insns, type_index);

  return true;
}

static void DecompileInstanceFieldAccess(u2 *insns, Code new_opcode) {
  u2 index = NextIndex();
  dexInstr_SetOpcode(insns, new_opcode);
  dexInstr_SetVRegC_22c(insns, index);
}

static void DecompileInvokeVirtual(u2 *insns, Code new_opcode, bool is_range) {
  u2 index = NextIndex();
  dexInstr_SetOpcode(insns, new_opcode);
  if (is_range) {
    dexInstr_SetVRegB_3rc(insns, index);
  } else {
    dexInstr_SetVRegB_35c(insns, index);
  }
}

bool vdex_decompiler_021_decompile(const u1 *dexFileBuf,
                                   dexMethod *pDexMethod,
                                   const vdex_data_array_t *quickenData,
                                   bool decompile_return_instruction) {
  if (quickenData->size == 0 && !decompile_return_instruction) {
    return true;
  }

  // Get method's CodeItem information
  u2 *pCode = NULL;
  u4 codeSize = 0;
  dex_getCodeItemInfo(dexFileBuf, pDexMethod, &pCode, &codeSize);

  u4 startCodeOff = dex_getFirstInstrOff(dexFileBuf, pDexMethod);

  // Initialize global data for every method that is decompiled
  initQuickenInfoTable(quickenData);
  initCodeIterator(pCode, codeSize, startCodeOff);

  log_dis("    quickening_size=%" PRIx32 " (%" PRIu32 ")\n", quickenData->size, quickenData->size);

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
        if (quicken_info_number_of_indices > 0) {
          // Only try to decompile NOP if there are more than 0 indices. Not having
          // any index happens when we unquicken a code item that only has
          // RETURN_VOID_NO_BARRIER as quickened instruction.
          hasCodeChange = DecompileNop(code_ptr);
        }
        break;
      case IGET_QUICK:
        CHECK_GT(quicken_info_number_of_indices, 0);
        DecompileInstanceFieldAccess(code_ptr, IGET);
        break;
      case IGET_WIDE_QUICK:
        CHECK_GT(quicken_info_number_of_indices, 0);
        DecompileInstanceFieldAccess(code_ptr, IGET_WIDE);
        break;
      case IGET_OBJECT_QUICK:
        CHECK_GT(quicken_info_number_of_indices, 0);
        DecompileInstanceFieldAccess(code_ptr, IGET_OBJECT);
        break;
      case IGET_BOOLEAN_QUICK:
        CHECK_GT(quicken_info_number_of_indices, 0);
        DecompileInstanceFieldAccess(code_ptr, IGET_BOOLEAN);
        break;
      case IGET_BYTE_QUICK:
        CHECK_GT(quicken_info_number_of_indices, 0);
        DecompileInstanceFieldAccess(code_ptr, IGET_BYTE);
        break;
      case IGET_CHAR_QUICK:
        CHECK_GT(quicken_info_number_of_indices, 0);
        DecompileInstanceFieldAccess(code_ptr, IGET_CHAR);
        break;
      case IGET_SHORT_QUICK:
        CHECK_GT(quicken_info_number_of_indices, 0);
        DecompileInstanceFieldAccess(code_ptr, IGET_SHORT);
        break;
      case IPUT_QUICK:
        CHECK_GT(quicken_info_number_of_indices, 0);
        DecompileInstanceFieldAccess(code_ptr, IPUT);
        break;
      case IPUT_BOOLEAN_QUICK:
        CHECK_GT(quicken_info_number_of_indices, 0);
        DecompileInstanceFieldAccess(code_ptr, IPUT_BOOLEAN);
        break;
      case IPUT_BYTE_QUICK:
        CHECK_GT(quicken_info_number_of_indices, 0);
        DecompileInstanceFieldAccess(code_ptr, IPUT_BYTE);
        break;
      case IPUT_CHAR_QUICK:
        CHECK_GT(quicken_info_number_of_indices, 0);
        DecompileInstanceFieldAccess(code_ptr, IPUT_CHAR);
        break;
      case IPUT_SHORT_QUICK:
        CHECK_GT(quicken_info_number_of_indices, 0);
        DecompileInstanceFieldAccess(code_ptr, IPUT_SHORT);
        break;
      case IPUT_WIDE_QUICK:
        CHECK_GT(quicken_info_number_of_indices, 0);
        DecompileInstanceFieldAccess(code_ptr, IPUT_WIDE);
        break;
      case IPUT_OBJECT_QUICK:
        CHECK_GT(quicken_info_number_of_indices, 0);
        DecompileInstanceFieldAccess(code_ptr, IPUT_OBJECT);
        break;
      case INVOKE_VIRTUAL_QUICK:
        CHECK_GT(quicken_info_number_of_indices, 0);
        DecompileInvokeVirtual(code_ptr, INVOKE_VIRTUAL, false);
        break;
      case INVOKE_VIRTUAL_RANGE_QUICK:
        CHECK_GT(quicken_info_number_of_indices, 0);
        DecompileInvokeVirtual(code_ptr, INVOKE_VIRTUAL_RANGE, true);
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

  if (quicken_index != quicken_info_number_of_indices) {
    if (quicken_index == 0) {
      LOGMSG(l_ERROR,
             "Failed to use any value in quickening info, potentially due to duplicate methods.");
    } else {
      LOGMSG(l_ERROR, "Failed to use all values in quickening info, '%zx' items not processed",
             quicken_info_number_of_indices - quicken_index);
      return false;
    }
  }

  return true;
}

void vdex_decompiler_021_walk(const u1 *dexFileBuf, dexMethod *pDexMethod) {
  // We have different code items in Standard Dex and Compact Dex
  u2 *pCode = NULL;
  u4 codeSize = 0;
  if (dex_checkType(dexFileBuf) == kNormalDex) {
    dexCode *pDexCode = (dexCode *)(dex_getDataAddr(dexFileBuf) + pDexMethod->codeOff);
    pCode = pDexCode->insns;
    codeSize = pDexCode->insnsSize;
  } else {
    cdexCode *pCdexCode = (cdexCode *)(dex_getDataAddr(dexFileBuf) + pDexMethod->codeOff);
    pCode = pCdexCode->insns;
    dex_DecodeCDexFields(pCdexCode, &codeSize, NULL, NULL, NULL, NULL, true);
  }

  u4 startCodeOff = dex_getFirstInstrOff(dexFileBuf, pDexMethod);
  initCodeIterator(pCode, codeSize, startCodeOff);
  while (isCodeIteratorDone() == false) {
    dex_dumpInstruction(dexFileBuf, code_ptr, cur_code_off, dex_pc, false);
    codeIteratorAdvance();
  }
}
