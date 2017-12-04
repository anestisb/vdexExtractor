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

#include "dex_decompiler.h"
#include "dex_decompiler_v10.h"
#include "dex_decompiler_v6.h"

static bool (*decompilePtr)(const u1 *, dexMethod *, const u1 *, u4, bool);
static void (*walkPtr)(const u1 *, dexMethod *, bool *);

void dexDecompiler_init(dexDecompiler_ver ver) {
  switch (ver) {
    case kDecompilerV6:
      decompilePtr = &dexDecompilerV6_decompile;
      walkPtr = &dexDecompilerV6_walk;
      break;
    case kDecompilerV10:
      decompilePtr = &dexDecompilerV10_decompile;
      walkPtr = &dexDecompilerV10_walk;
      break;
    default:
      LOGMSG(l_FATAL, "Invalid Dex decompiler version");
  }
}

bool dexDecompiler_decompile(const u1 *dexFileBuf,
                             dexMethod *pDexMethod,
                             const u1 *quickening_info,
                             u4 quickening_size,
                             bool decompile_return_instruction) {
  return (*decompilePtr)(dexFileBuf, pDexMethod, quickening_info, quickening_size,
                         decompile_return_instruction);
}

void dexDecompiler_walk(const u1 *dexFileBuf, dexMethod *pDexMethod, bool *foundLogUtilCall) {
  (*walkPtr)(dexFileBuf, pDexMethod, foundLogUtilCall);
}
