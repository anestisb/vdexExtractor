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

#include "vdex_decompiler_027.h"

#include "../utils.h"

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

void vdex_decompiler_027_walk(const u1 *dexFileBuf, dexMethod *pDexMethod) {
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
