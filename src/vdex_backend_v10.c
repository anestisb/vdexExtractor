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

#include <sys/mman.h>

#include "dex_decompiler_v10.h"
#include "out_writer.h"
#include "utils.h"
#include "vdex.h"
#include "vdex_backend_v10.h"

static const u1 *quickening_info_ptr;
static const unaligned_u4 *current_code_item_ptr;
static const unaligned_u4 *current_code_item_end;

static void QuickeningInfoItInit(u4 dex_file_idx,
                                 u4 numberOfDexFiles,
                                 const u1 *quicken_ptr,
                                 u4 quicken_size) {
  quickening_info_ptr = quicken_ptr;
  const unaligned_u4 *dex_file_indices =
      (unaligned_u4 *)(quicken_ptr + quicken_size - numberOfDexFiles * sizeof(u4));
  current_code_item_end = (dex_file_idx == numberOfDexFiles - 1)
                              ? dex_file_indices
                              : (unaligned_u4 *)(quicken_ptr + dex_file_indices[dex_file_idx + 1]);
  current_code_item_ptr = (unaligned_u4 *)(quicken_ptr + dex_file_indices[dex_file_idx]);
}

static bool QuickeningInfoItDone() { return current_code_item_ptr == current_code_item_end; }

static void QuickeningInfoItAdvance() { current_code_item_ptr += 2; }

static u4 QuickeningInfoItGetCurrentCodeItemOffset() { return current_code_item_ptr[0]; }

static const u1 *QuickeningInfoItGetCurrentPtr() {
  return quickening_info_ptr + current_code_item_ptr[1] + sizeof(u4);
}

static u4 QuickeningInfoItGetCurrentSize() {
  return *(unaligned_u4 *)(quickening_info_ptr + current_code_item_ptr[1]);
}

int vdex_process_v10(const char *VdexFileName, const u1 *cursor, const runArgs_t *pRunArgs) {
  // Update Dex disassembler engine status
  dex_setDisassemblerStatus(pRunArgs->enableDisassembler);

  const vdexHeader *pVdexHeader = (const vdexHeader *)cursor;
  const u1 *dexFileBuf = NULL;
  u4 offset = 0;

  // For each Dex file
  for (size_t dex_file_idx = 0; dex_file_idx < pVdexHeader->numberOfDexFiles; ++dex_file_idx) {
    QuickeningInfoItInit(dex_file_idx, pVdexHeader->numberOfDexFiles,
                         vdex_GetQuickeningInfo(cursor), vdex_GetQuickeningInfoSize(cursor));

    dexFileBuf = vdex_GetNextDexFileData(cursor, &offset);
    if (dexFileBuf == NULL) {
      LOGMSG(l_ERROR, "Failed to extract 'classes%zu.dex' - skipping", dex_file_idx);
      continue;
    }

    const dexHeader *pDexHeader = (const dexHeader *)dexFileBuf;

    // Check if valid Dex file
    dex_dumpHeaderInfo(pDexHeader);
    if (!dex_isValidDexMagic(pDexHeader)) {
      LOGMSG(l_ERROR, "'classes%zu.dex' is an invalid Dex file - skipping", dex_file_idx);
      continue;
    }

    // For each class
    log_dis("file #%zu: classDefsSize=%" PRIu32 "\n", dex_file_idx, pDexHeader->classDefsSize);
    for (u4 i = 0; i < pDexHeader->classDefsSize; ++i) {
      const dexClassDef *pDexClassDef = dex_getClassDef(dexFileBuf, i);
      dex_dumpClassInfo(dexFileBuf, i);

      // Cursor for currently processed class data item
      const u1 *curClassDataCursor;
      if (pDexClassDef->classDataOff == 0) {
        continue;
      } else {
        curClassDataCursor = dexFileBuf + pDexClassDef->classDataOff;
      }

      dexClassDataHeader pDexClassDataHeader;
      memset(&pDexClassDataHeader, 0, sizeof(dexClassDataHeader));
      dex_readClassDataHeader(&curClassDataCursor, &pDexClassDataHeader);

      // Skip static fields
      for (u4 j = 0; j < pDexClassDataHeader.staticFieldsSize; ++j) {
        dexField pDexField;
        memset(&pDexField, 0, sizeof(dexField));
        dex_readClassDataField(&curClassDataCursor, &pDexField);
      }

      // Skip instance fields
      for (u4 j = 0; j < pDexClassDataHeader.instanceFieldsSize; ++j) {
        dexField pDexField;
        memset(&pDexField, 0, sizeof(dexField));
        dex_readClassDataField(&curClassDataCursor, &pDexField);
      }

      // For each direct method
      for (u4 j = 0; j < pDexClassDataHeader.directMethodsSize; ++j) {
        dexMethod curDexMethod;
        memset(&curDexMethod, 0, sizeof(dexMethod));
        dex_readClassDataMethod(&curClassDataCursor, &curDexMethod);
        dex_dumpMethodInfo(dexFileBuf, &curDexMethod, j, "direct");

        // Skip empty methods
        if (curDexMethod.codeOff == 0) {
          continue;
        }

        if (pRunArgs->unquicken) {
          const u1 *quickening_ptr = QuickeningInfoItGetCurrentPtr();
          u4 quickening_size = QuickeningInfoItGetCurrentSize();
          if (!QuickeningInfoItDone() &&
              curDexMethod.codeOff == QuickeningInfoItGetCurrentCodeItemOffset()) {
            QuickeningInfoItAdvance();
          } else {
            quickening_ptr = NULL;
            quickening_size = 0;
          }
          if (!dexDecompilerV10_decompile(dexFileBuf, &curDexMethod, quickening_ptr,
                                          quickening_size, true)) {
            LOGMSG(l_ERROR, "Failed to decompile Dex file");
            return -1;
          }
        } else {
          dexDecompilerV10_walk(dexFileBuf, &curDexMethod);
        }
      }

      // For each virtual method
      for (u4 j = 0; j < pDexClassDataHeader.virtualMethodsSize; ++j) {
        dexMethod curDexMethod;
        memset(&curDexMethod, 0, sizeof(dexMethod));
        dex_readClassDataMethod(&curClassDataCursor, &curDexMethod);
        dex_dumpMethodInfo(dexFileBuf, &curDexMethod, j, "virtual");

        // Skip native or abstract methods
        if (curDexMethod.codeOff == 0) {
          continue;
        }

        if (pRunArgs->unquicken) {
          const u1 *quickening_ptr = QuickeningInfoItGetCurrentPtr();
          u4 quickening_size = QuickeningInfoItGetCurrentSize();
          if (!QuickeningInfoItDone() &&
              curDexMethod.codeOff == QuickeningInfoItGetCurrentCodeItemOffset()) {
            QuickeningInfoItAdvance();
          } else {
            quickening_ptr = NULL;
            quickening_size = 0;
          }
          if (!dexDecompilerV10_decompile(dexFileBuf, &curDexMethod, quickening_ptr,
                                          quickening_size, true)) {
            LOGMSG(l_ERROR, "Failed to decompile Dex file");
            return -1;
          }
        } else {
          dexDecompilerV10_walk(dexFileBuf, &curDexMethod);
        }
      }
    }

    if (pRunArgs->unquicken) {
      // All QuickeningInfo data should have been consumed
      if (!QuickeningInfoItDone()) {
        LOGMSG(l_ERROR, "Failed to use all quickening info");
        return -1;
      }
      // If unquicken was successful original checksum should verify
      u4 curChecksum = dex_computeDexCRC(dexFileBuf, pDexHeader->fileSize);
      if (curChecksum != pDexHeader->checksum) {
        LOGMSG(l_ERROR,
               "Unexpected checksum (%" PRIx32 " vs %" PRIx32 ") - failed to unquicken Dex file",
               curChecksum, pDexHeader->checksum);
        return -1;
      }
    } else {
      // Repair CRC if not decompiling so we can still run Dex parsing tools against output
      dex_repairDexCRC(dexFileBuf, pDexHeader->fileSize);
    }

    if (!outWriter_DexFile(pRunArgs, VdexFileName, dex_file_idx, dexFileBuf,
                           pDexHeader->fileSize)) {
      return -1;
    }
  }

  return pVdexHeader->numberOfDexFiles;
}
