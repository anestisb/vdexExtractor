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

bool vdex_isMagicValid(const uint8_t *cursor) {
  const vdexHeader *pVdexHeader = (const vdexHeader *)cursor;
  return (memcmp(pVdexHeader->magic_, kVdexMagic, sizeof(kVdexMagic)) == 0);
}

bool vdex_isVersionValid(const uint8_t *cursor) {
  const vdexHeader *pVdexHeader = (const vdexHeader *)cursor;
  return (memcmp(pVdexHeader->version_, kVdexVersion, sizeof(kVdexVersion)) == 0);
}

bool vdex_isValidVdex(const uint8_t *cursor) {
  return vdex_isMagicValid(cursor) && vdex_isVersionValid(cursor);
}

bool vdex_hasDexSection(const uint8_t *cursor) {
  const vdexHeader *pVdexHeader = (const vdexHeader *)cursor;
  return pVdexHeader->dex_size_ != 0;
}

uint32_t vdex_GetSizeOfChecksumsSection(const uint8_t *cursor) {
  const vdexHeader *pVdexHeader = (const vdexHeader *)cursor;
  return sizeof(VdexChecksum) * pVdexHeader->number_of_dex_files_;
}

const uint8_t *vdex_DexBegin(const uint8_t *cursor) {
  return cursor + sizeof(vdexHeader) + vdex_GetSizeOfChecksumsSection(cursor);
}

const uint8_t *vdex_DexEnd(const uint8_t *cursor) {
  const vdexHeader *pVdexHeader = (const vdexHeader *)cursor;
  return vdex_DexBegin(cursor) + pVdexHeader->dex_size_;
}

const uint8_t *vdex_GetNextDexFileData(const uint8_t *cursor, uint32_t *offset) {
  if (*offset == 0) {
    if (vdex_hasDexSection(cursor)) {
      const uint8_t *dexBuf = vdex_DexBegin(cursor);
      *offset = sizeof(vdexHeader) + vdex_GetSizeOfChecksumsSection(cursor);
      LOGMSG(l_DEBUG, "Processing first DEX file at offset:0x%x", *offset);

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
    const uint8_t *dexBuf = cursor + *offset;
    const uint8_t *dexBufMax = dexBuf + pDexHeader->fileSize;
    if (dexBufMax == vdex_DexEnd(cursor)) {
      LOGMSG(l_DEBUG, "Processing last DEX file at offset:0x%x", *offset);
    } else if (dexBufMax <= vdex_DexEnd(cursor)) {
      LOGMSG(l_DEBUG, "Processing DEX file at offset:0x%x", *offset);
    } else {
      LOGMSG(l_ERROR, "Invalid cursor offset '0x%x'", *offset);
      return NULL;
    }

    // Adjust offset to point at the end of current Dex file
    *offset += pDexHeader->fileSize;
    return dexBuf;
  }
}

uint32_t vdex_GetLocationChecksum(const uint8_t *cursor, uint32_t fileIdx) {
  return (cursor + sizeof(vdexHeader))[fileIdx];
}

const uint8_t *vdex_GetVerifierDepsData(const uint8_t *cursor) {
  const vdexHeader *pVdexHeader = (const vdexHeader *)cursor;
  return vdex_DexBegin(cursor) + pVdexHeader->dex_size_;
}

uint32_t vdex_GetVerifierDepsDataSize(const uint8_t *cursor) {
  const vdexHeader *pVdexHeader = (const vdexHeader *)cursor;
  return pVdexHeader->verifier_deps_size_;
}

const uint8_t *vdex_GetQuickeningInfo(const uint8_t *cursor) {
  const vdexHeader *pVdexHeader = (const vdexHeader *)cursor;
  return vdex_GetVerifierDepsData(cursor) + pVdexHeader->verifier_deps_size_;
}

uint32_t vdex_GetQuickeningInfoSize(const uint8_t *cursor) {
  const vdexHeader *pVdexHeader = (const vdexHeader *)cursor;
  return pVdexHeader->quickening_info_size_;
}

bool vdex_Unquicken(const uint8_t *cursor) {
  if (vdex_GetQuickeningInfoSize(cursor) == 0) {
    // If there is no quickening info, we bail early, as the code below expects at
    // least the size of quickening data for each method that has a code item.
    return true;
  }

  const vdexHeader *pVdexHeader = (const vdexHeader *)cursor;
  const uint8_t *quickening_info_ptr = vdex_GetQuickeningInfo(cursor);
  const uint8_t *const quickening_info_end =
      vdex_GetQuickeningInfo(cursor) + vdex_GetQuickeningInfoSize(cursor);

  const uint8_t *dexFileBuf = NULL;
  uint32_t offset = 0;

  // For each Dex file
  for (size_t dex_file_idx = 0; dex_file_idx < pVdexHeader->number_of_dex_files_; ++dex_file_idx) {
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
    dexClassDef *dexClassDefs = (dexClassDef *)(dexFileBuf + pDexHeader->classDefsOff);

    for (uint32_t i = 0; i < pDexHeader->classDefsSize; ++i) {
      LOGMSG(l_VDEBUG, "\tclass #%" PRIu32 ": class_data_off=%" PRIu32, i,
             dexClassDefs[i].classDataOff);

      // Cursor for currently processed class data item
      const uint8_t *curClassDataCursor;
      if (dexClassDefs[i].classDataOff == 0) {
        continue;
      } else {
        curClassDataCursor = dexFileBuf + dexClassDefs[i].classDataOff;
      }

      dexClassDataHeader pDexClassDataHeader;
      memset(&pDexClassDataHeader, 0, sizeof(dexClassDataHeader));
      dex_readClassDataHeader(&curClassDataCursor, &pDexClassDataHeader);

      LOGMSG(l_VDEBUG, "\t\tstatic_fields=%" PRIu32 ", instance_fields=%" PRIu32
                       ", direct_methods=%" PRIu32 ", virtual_methods=%" PRIu32,
             i, pDexClassDataHeader.staticFieldsSize, pDexClassDataHeader.instanceFieldsSize,
             pDexClassDataHeader.directMethodsSize, pDexClassDataHeader.virtualMethodsSize);

      // Skip static fields
      for (uint32_t j = 0; j < pDexClassDataHeader.staticFieldsSize; ++j) {
        dexField pDexField;
        memset(&pDexField, 0, sizeof(dexField));
        dex_readClassDataField(&curClassDataCursor, &pDexField);
      }

      // Skip instance fields
      for (uint32_t j = 0; j < pDexClassDataHeader.instanceFieldsSize; ++j) {
        dexField pDexField;
        memset(&pDexField, 0, sizeof(dexField));
        dex_readClassDataField(&curClassDataCursor, &pDexField);
      }

      // For each direct method
      for (uint32_t j = 0; j < pDexClassDataHeader.directMethodsSize; ++j) {
        dexMethod pDexMethod;
        memset(&pDexMethod, 0, sizeof(dexMethod));
        dex_readClassDataMethod(&curClassDataCursor, &pDexMethod);
        LOGMSG(l_VDEBUG, "\t\t\tdirect_method #%" PRIu32 ": codeOff=%" PRIx32, j,
               pDexMethod.codeOff);

        // Skip empty methods
        if (pDexMethod.codeOff == 0) {
          continue;
        }

        // Get method code offset and revert quickened instructions
        dexCode *pDexCode = (dexCode *)(dexFileBuf + pDexMethod.codeOff);

        // For quickening info blob the first 4bytes are the inner blobs size
        uint32_t quickening_size = *(uint32_t *)quickening_info_ptr;
        quickening_info_ptr += sizeof(uint32_t);
        if (!dexDecompiler_decompile(pDexCode, dex_getFirstInstrOff(&pDexMethod),
                                     quickening_info_ptr, quickening_size, true)) {
          LOGMSG(l_ERROR, "Failed to decompile DEX file");
          return false;
        }
        quickening_info_ptr += quickening_size;
      }

      // For each virtual method
      for (uint32_t j = 0; j < pDexClassDataHeader.virtualMethodsSize; ++j) {
        dexMethod pDexMethod;
        memset(&pDexMethod, 0, sizeof(dexMethod));
        dex_readClassDataMethod(&curClassDataCursor, &pDexMethod);
        LOGMSG(l_VDEBUG, "\t\t\tvirtual_method #%" PRIu32 ": codeOff=%" PRIx32, j,
               pDexMethod.codeOff);

        // Skip native or abstract methods
        if (pDexMethod.codeOff == 0) {
          continue;
        }

        // Get method code offset and revert quickened instructions
        dexCode *pDexCode = (dexCode *)(dexFileBuf + pDexMethod.codeOff);

        // For quickening info blob the first 4bytes are the inner blobs size
        uint32_t quickening_size = *(uint32_t *)quickening_info_ptr;
        quickening_info_ptr += sizeof(uint32_t);
        if (!dexDecompiler_decompile(pDexCode, dex_getFirstInstrOff(&pDexMethod),
                                     quickening_info_ptr, quickening_size, true)) {
          LOGMSG(l_ERROR, "Failed to decompile DEX file");
          return false;
        }
        quickening_info_ptr += quickening_size;
      }
    }

    // If unquicken was successful original checksum should verify
    uint32_t curChecksum = dex_computeDexCRC(dexFileBuf, pDexHeader->fileSize);
    if (curChecksum != pDexHeader->checksum) {
      LOGMSG(l_ERROR,
             "Unexpected checksum (%" PRIx32 " vs %" PRIx32 ") - failed to unquicken DEX file",
             curChecksum, pDexHeader->checksum);
      return false;
    }
  }

  if (quickening_info_ptr != quickening_info_end) {
    LOGMSG(l_ERROR, "Failed to process all outer quickening info");
    return false;
  }

  return true;
}
