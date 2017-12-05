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

#include "dex_decompiler_v6.h"
#include "out_writer.h"
#include "utils.h"
#include "vdex.h"
#include "vdex_backend_v6.h"

int vdex_process_v6(const char *VdexFileName, const u1 *cursor, const runArgs_t *pRunArgs) {
  // Update Dex disassembler engine status
  dex_setDisassemblerStatus(pRunArgs->enableDisassembler);

  // Measure time spend to process all Dex files of a Vdex file
  struct timespec timer;
  utils_startTimer(&timer);

  const vdexHeader *pVdexHeader = (const vdexHeader *)cursor;
  const u1 *quickening_info_ptr = vdex_GetQuickeningInfo(cursor);
  const u1 *const quickening_info_end =
      vdex_GetQuickeningInfo(cursor) + vdex_GetQuickeningInfoSize(cursor);

  const u1 *dexFileBuf = NULL;
  u4 offset = 0;

  // For each Dex file
  for (size_t dex_file_idx = 0; dex_file_idx < pVdexHeader->numberOfDexFiles; ++dex_file_idx) {
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

        if (pRunArgs->unquicken && vdex_GetQuickeningInfoSize(cursor) != 0) {
          // For quickening info blob the first 4bytes are the inner blobs size
          u4 quickening_size = *(u4 *)quickening_info_ptr;
          quickening_info_ptr += sizeof(u4);
          if (!dexDecompilerV6_decompile(dexFileBuf, &curDexMethod, quickening_info_ptr,
                                         quickening_size, true)) {
            LOGMSG(l_ERROR, "Failed to decompile Dex file");
            return -1;
          }
          quickening_info_ptr += quickening_size;
        } else {
          dexDecompilerV6_walk(dexFileBuf, &curDexMethod);
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

        if (pRunArgs->unquicken && vdex_GetQuickeningInfoSize(cursor) != 0) {
          // For quickening info blob the first 4bytes are the inner blobs size
          u4 quickening_size = *(u4 *)quickening_info_ptr;
          quickening_info_ptr += sizeof(u4);
          if (!dexDecompilerV6_decompile(dexFileBuf, &curDexMethod, quickening_info_ptr,
                                         quickening_size, true)) {
            LOGMSG(l_ERROR, "Failed to decompile Dex file");
            return -1;
          }
          quickening_info_ptr += quickening_size;
        } else {
          dexDecompilerV6_walk(dexFileBuf, &curDexMethod);
        }
      }
    }

    if (pRunArgs->unquicken) {
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

  if (pRunArgs->unquicken && (quickening_info_ptr != quickening_info_end)) {
    LOGMSG(l_ERROR, "Failed to process all quickening info data");
    return -1;
  }

  // Get elapsed time in ns
  long timeSpend = utils_endTimer(&timer);
  LOGMSG(l_DEBUG, "Took %ld ms to process Vdex file", timeSpend / 1000000);

  return pVdexHeader->numberOfDexFiles;
}
