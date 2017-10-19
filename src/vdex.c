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

#include "vdex.h"
#include "dex_decompiler.h"
#include "utils.h"

bool vdex_isMagicValid(const u1 *cursor) {
  const vdexHeader *pVdexHeader = (const vdexHeader *)cursor;
  return (memcmp(pVdexHeader->magic, kVdexMagic, sizeof(kVdexMagic)) == 0);
}

bool vdex_isVersionValid(const u1 *cursor) {
  const vdexHeader *pVdexHeader = (const vdexHeader *)cursor;
  for (u4 i = 0; i < kNumVdexVersions; i++) {
    if (memcmp(pVdexHeader->version, kVdexMagicVersions[i], kVdexVersionLen) == 0) {
      LOGMSG(l_DEBUG, "Vdex version '%s' detected", pVdexHeader->version);
      return true;
    }
  }
  return false;
}

bool vdex_isValidVdex(const u1 *cursor) {
  return vdex_isMagicValid(cursor) && vdex_isVersionValid(cursor);
}

bool vdex_hasDexSection(const u1 *cursor) {
  const vdexHeader *pVdexHeader = (const vdexHeader *)cursor;
  return pVdexHeader->dexSize != 0;
}

u4 vdex_GetSizeOfChecksumsSection(const u1 *cursor) {
  const vdexHeader *pVdexHeader = (const vdexHeader *)cursor;
  return sizeof(VdexChecksum) * pVdexHeader->numberOfDexFiles;
}

const u1 *vdex_DexBegin(const u1 *cursor) {
  return cursor + sizeof(vdexHeader) + vdex_GetSizeOfChecksumsSection(cursor);
}

u4 vdex_DexBeginOffset(const u1 *cursor) {
  return sizeof(vdexHeader) + vdex_GetSizeOfChecksumsSection(cursor);
}

const u1 *vdex_DexEnd(const u1 *cursor) {
  const vdexHeader *pVdexHeader = (const vdexHeader *)cursor;
  return vdex_DexBegin(cursor) + pVdexHeader->dexSize;
}

u4 vdex_DexEndOffset(const u1 *cursor) {
  const vdexHeader *pVdexHeader = (const vdexHeader *)cursor;
  return vdex_DexBeginOffset(cursor) + pVdexHeader->dexSize;
}

const u1 *vdex_GetNextDexFileData(const u1 *cursor, u4 *offset) {
  if (*offset == 0) {
    if (vdex_hasDexSection(cursor)) {
      const u1 *dexBuf = vdex_DexBegin(cursor);
      *offset = sizeof(vdexHeader) + vdex_GetSizeOfChecksumsSection(cursor);
      LOGMSG(l_DEBUG, "Processing first Dex file at offset:0x%x", *offset);

      // Adjust offset to point at the end of current Dex file
      dexHeader *pDexHeader = (dexHeader *)(dexBuf);
      *offset += pDexHeader->fileSize;
      return dexBuf;
    } else {
      return NULL;
    }
  } else {
    dexHeader *pDexHeader = (dexHeader *)(cursor + *offset);

    // Check boundaries
    const u1 *dexBuf = cursor + *offset;
    const u1 *dexBufMax = dexBuf + pDexHeader->fileSize;
    if (dexBufMax == vdex_DexEnd(cursor)) {
      LOGMSG(l_DEBUG, "Processing last Dex file at offset:0x%x", *offset);
    } else if (dexBufMax <= vdex_DexEnd(cursor)) {
      LOGMSG(l_DEBUG, "Processing Dex file at offset:0x%x", *offset);
    } else {
      LOGMSG(l_ERROR, "Invalid cursor offset '0x%x'", *offset);
      return NULL;
    }

    // Adjust offset to point at the end of current Dex file
    *offset += pDexHeader->fileSize;
    return dexBuf;
  }
}

u4 vdex_GetLocationChecksum(const u1 *cursor, u4 fileIdx) {
  u4 *checksums = (u4 *)(cursor + sizeof(vdexHeader));
  return checksums[fileIdx];
}

const u1 *vdex_GetVerifierDepsData(const u1 *cursor) {
  const vdexHeader *pVdexHeader = (const vdexHeader *)cursor;
  return vdex_DexBegin(cursor) + pVdexHeader->dexSize;
}

u4 vdex_GetVerifierDepsDataOffset(const u1 *cursor) {
  const vdexHeader *pVdexHeader = (const vdexHeader *)cursor;
  return vdex_DexBeginOffset(cursor) + pVdexHeader->dexSize;
}

u4 vdex_GetVerifierDepsDataSize(const u1 *cursor) {
  const vdexHeader *pVdexHeader = (const vdexHeader *)cursor;
  return pVdexHeader->verifierDepsSize;
}

const u1 *vdex_GetQuickeningInfo(const u1 *cursor) {
  const vdexHeader *pVdexHeader = (const vdexHeader *)cursor;
  return vdex_GetVerifierDepsData(cursor) + pVdexHeader->verifierDepsSize;
}

u4 vdex_GetQuickeningInfoOffset(const u1 *cursor) {
  const vdexHeader *pVdexHeader = (const vdexHeader *)cursor;
  return vdex_GetVerifierDepsDataOffset(cursor) + pVdexHeader->verifierDepsSize;
}

u4 vdex_GetQuickeningInfoSize(const u1 *cursor) {
  const vdexHeader *pVdexHeader = (const vdexHeader *)cursor;
  return pVdexHeader->quickeningInfoSize;
}

void vdex_dumpHeaderInfo(const u1 *cursor) {
  const vdexHeader *pVdexHeader = (const vdexHeader *)cursor;

  LOGMSG(l_VDEBUG, "------ Vdex Header Info ------");
  LOGMSG(l_VDEBUG, "magic header & version      : %.4s-%.4s", pVdexHeader->magic,
         pVdexHeader->version);
  LOGMSG(l_VDEBUG, "number of dex files         : %" PRIx32 " (%" PRIu32 ")",
         pVdexHeader->numberOfDexFiles, pVdexHeader->numberOfDexFiles);
  LOGMSG(l_VDEBUG, "dex size (overall)          : %" PRIx32 " (%" PRIu32 ")",
         pVdexHeader->dexSize, pVdexHeader->dexSize);
  LOGMSG(l_VDEBUG, "verifier dependencies size  : %" PRIx32 " (%" PRIu32 ")",
         pVdexHeader->verifierDepsSize, pVdexHeader->verifierDepsSize);
  LOGMSG(l_VDEBUG, "verifier dependencies offset: %" PRIx32 " (%" PRIu32 ")",
         vdex_GetVerifierDepsDataOffset(cursor), vdex_GetVerifierDepsDataOffset(cursor));
  LOGMSG(l_VDEBUG, "quickening info size        : %" PRIx32 " (%" PRIu32 ")",
         pVdexHeader->quickeningInfoSize, pVdexHeader->quickeningInfoSize);
  LOGMSG(l_VDEBUG, "quickening info offset      : %" PRIx32 " (%" PRIu32 ")",
         vdex_GetQuickeningInfoOffset(cursor), vdex_GetQuickeningInfoOffset(cursor));
  LOGMSG(l_VDEBUG, "dex files info              :")

  for (u4 i = 0; i < pVdexHeader->numberOfDexFiles; ++i) {
    LOGMSG(l_VDEBUG, "  [%" PRIu32 "] location checksum : %" PRIx32 " (%" PRIu32 ")", i,
           vdex_GetLocationChecksum(cursor, i), vdex_GetLocationChecksum(cursor, i));
  }
  LOGMSG(l_VDEBUG, "------------------------------");
}

bool vdex_Unquicken(const u1 *cursor) {
  if (vdex_GetQuickeningInfoSize(cursor) == 0) {
    // If there is no quickening info, we bail early, as the code below expects at
    // least the size of quickening data for each method that has a code item.
    return true;
  }

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
      LOGMSG(l_ERROR, "Failed to unquicken 'classes%zu.dex' - skipping", dex_file_idx);
      continue;
    }

    // For each class
    LOGMSG(l_VDEBUG, "file #%zu: classDefsSize=%" PRIu32, dex_file_idx, pDexHeader->classDefsSize);
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

        // Get method code offset and revert quickened instructions
        dexCode *pDexCode = (dexCode *)(dexFileBuf + curDexMethod.codeOff);

        // For quickening info blob the first 4bytes are the inner blobs size
        u4 quickening_size = *(u4 *)quickening_info_ptr;
        quickening_info_ptr += sizeof(u4);
        if (!dexDecompiler_decompile(dexFileBuf, pDexCode, dex_getFirstInstrOff(&curDexMethod),
                                     quickening_info_ptr, quickening_size, true)) {
          LOGMSG(l_ERROR, "Failed to decompile Dex file");
          return false;
        }
        quickening_info_ptr += quickening_size;
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

        // Get method code offset and revert quickened instructions
        dexCode *pDexCode = (dexCode *)(dexFileBuf + curDexMethod.codeOff);

        // For quickening info blob the first 4bytes are the inner blobs size
        u4 quickening_size = *(u4 *)quickening_info_ptr;
        quickening_info_ptr += sizeof(u4);
        if (!dexDecompiler_decompile(dexFileBuf, pDexCode, dex_getFirstInstrOff(&curDexMethod),
                                     quickening_info_ptr, quickening_size, true)) {
          LOGMSG(l_ERROR, "Failed to decompile Dex file");
          return false;
        }
        quickening_info_ptr += quickening_size;
      }
    }

    // If unquicken was successful original checksum should verify
    u4 curChecksum = dex_computeDexCRC(dexFileBuf, pDexHeader->fileSize);
    if (curChecksum != pDexHeader->checksum) {
      LOGMSG(l_ERROR,
             "Unexpected checksum (%" PRIx32 " vs %" PRIx32 ") - failed to unquicken Dex file",
             curChecksum, pDexHeader->checksum);
      return false;
    }
  }

  if (quickening_info_ptr != quickening_info_end) {
    LOGMSG(l_ERROR, "Failed to process all quickening info data");
    return false;
  }

  return true;
}
