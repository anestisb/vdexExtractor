/*

   vdexExtractor
   -----------------------------------------

   Anestis Bechtsoudis <anestis@census-labs.com>
   Copyright 2017 - 2020 by CENSUS S.A. All Rights Reserved.

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

#include "vdex_027.h"

#include "../out_writer.h"
#include "../utils.h"
#include "vdex_backend_027.h"

bool vdex_027_isMagicValid(const u1 *cursor) {
  const vdexHeader_027 *pVdexHeader = (const vdexHeader_027 *)cursor;
  return (memcmp(pVdexHeader->magic, kVdexMagic, sizeof(kVdexMagic)) == 0);
}

bool vdex_027_IsVdexVersionValid(const u1 *cursor) {
  const vdexHeader_027 *pVdexHeader = (const vdexHeader_027 *)cursor;
  return (memcmp(pVdexHeader->vdexVersion, kVdexVersion_027, sizeof(kVdexVersion_027)) == 0);
}

bool vdex_027_isValidVdex(const u1 *cursor) {
  return vdex_027_isMagicValid(cursor) && vdex_027_IsVdexVersionValid(cursor);
}

const vdexSectionHeader_027 *vdex_027_GetSectionHeader(const u1 *cursor, u4 index) {
  const vdexHeader_027 *pVdexHeader = (const vdexHeader_027 *)cursor;
  CHECK_LT(index, pVdexHeader->numberOfSections);
  return (vdexSectionHeader_027 *)(cursor + sizeof(vdexHeader_027) + index *
          sizeof(vdexSectionHeader_027));
}

bool vdex_027_hasDexSection(const u1 *cursor) {
  const vdexSectionHeader_027 *pSectHeader = vdex_027_GetSectionHeader(cursor, kDexFileSection);
  return pSectHeader->sectionSize != 0u;
}

u4 vdex_027_GetNumberOfDexFiles(const u1 *cursor) {
  const vdexSectionHeader_027 *pSectHeader = vdex_027_GetSectionHeader(cursor, kChecksumSection);
  return pSectHeader->sectionSize / sizeof(VdexChecksum);
}

const VdexChecksum *vdex_027_GetDexChecksumsArray(const u1 *cursor) {
  const vdexSectionHeader_027 *pSectHeader = vdex_027_GetSectionHeader(cursor, kChecksumSection);
  return (VdexChecksum *)(cursor + pSectHeader->sectionOffset);
}

const u1 *vdex_027_DexBegin(const u1 *cursor) {
  CHECK(vdex_027_hasDexSection(cursor));
  const vdexSectionHeader_027 *pSectHeader = vdex_027_GetSectionHeader(cursor, kDexFileSection);
  return cursor + pSectHeader->sectionOffset;
}

u4 vdex_027_DexBeginOffset(const u1 *cursor) {
  CHECK(vdex_027_hasDexSection(cursor));
  const vdexSectionHeader_027 *pSectHeader = vdex_027_GetSectionHeader(cursor, kDexFileSection);
  return pSectHeader->sectionOffset;
}

const u1 *vdex_027_DexEnd(const u1 *cursor) {
  CHECK(vdex_027_hasDexSection(cursor));
  const vdexSectionHeader_027 *pSectHeader = vdex_027_GetSectionHeader(cursor, kDexFileSection);
  return vdex_027_DexBegin(cursor) + pSectHeader->sectionSize;
}

u4 vdex_027_DexEndOffset(const u1 *cursor) {
  CHECK(vdex_027_hasDexSection(cursor));
  const vdexSectionHeader_027 *pSectHeader = vdex_027_GetSectionHeader(cursor, kDexFileSection);
  return vdex_027_DexBeginOffset(cursor) + pSectHeader->sectionSize;
}

u4 vdex_027_GetLocationChecksum(const u1 *cursor, u4 fileIdx) {
  CHECK_LT(fileIdx, vdex_027_GetNumberOfDexFiles(cursor));
  u4 *checksums = (u4 *)vdex_027_GetDexChecksumsArray(cursor);
  return checksums[fileIdx];
}

void vdex_027_SetLocationChecksum(const u1 *cursor, u4 fileIdx, u4 value) {
  CHECK_LT(fileIdx, vdex_027_GetNumberOfDexFiles(cursor));
  u4 *checksums = (u4 *)vdex_027_GetDexChecksumsArray(cursor);
  checksums[fileIdx] = value;
}

void vdex_027_dumpHeaderInfo(const u1 *cursor) {
  const vdexHeader_027 *pVdexHeader = (const vdexHeader_027 *)cursor;
  u4 numberOfDexFiles = vdex_027_GetNumberOfDexFiles(cursor);
  const vdexSectionHeader_027 *pDepsSectHeader = vdex_027_GetSectionHeader(cursor,
                                                                           kVerifierDepsSection);
  const vdexSectionHeader_027 *pTypeSectHeader = vdex_027_GetSectionHeader(cursor,
                                                                           kTypeLookupTableSection);
  const vdexSectionHeader_027 *pDexSectHeader = vdex_027_GetSectionHeader(cursor,
                                                                           kDexFileSection);

  LOGMSG_RAW(l_DEBUG, "------ Vdex Header Info -------\n");
  LOGMSG_RAW(l_DEBUG, "magic header                  : %.4s\n", pVdexHeader->magic);
  LOGMSG_RAW(l_DEBUG, "vdex version                  : %.4s\n", pVdexHeader->vdexVersion);
  LOGMSG_RAW(l_DEBUG, "number of dex files           : %" PRIx32 " (%" PRIu32 ")\n",
             numberOfDexFiles, numberOfDexFiles);
  LOGMSG_RAW(l_DEBUG, "dex file section size         : %" PRIx32 " (%" PRIu32 ")\n",
             pDexSectHeader->sectionSize, pDexSectHeader->sectionSize);
  LOGMSG_RAW(l_DEBUG, "dex file section offset       : %" PRIx32 " (%" PRIu32 ")\n",
             pDexSectHeader, pDexSectHeader->sectionOffset);
  LOGMSG_RAW(l_DEBUG, "verifier dependencies size    : %" PRIx32 " (%" PRIu32 ")\n",
             pDepsSectHeader->sectionSize, pDepsSectHeader->sectionSize);
  LOGMSG_RAW(l_DEBUG, "verifier dependencies offset  : %" PRIx32 " (%" PRIu32 ")\n",
             pDepsSectHeader->sectionOffset, pDepsSectHeader->sectionOffset);
  LOGMSG_RAW(l_DEBUG, "type lookup table size        : %" PRIx32 " (%" PRIu32 ")\n",
             pTypeSectHeader->sectionSize, pTypeSectHeader->sectionSize);
  LOGMSG_RAW(l_DEBUG, "type lookup table offset      : %" PRIx32 " (%" PRIu32 ")\n",
             pTypeSectHeader->sectionOffset, pTypeSectHeader->sectionOffset);
  if (vdex_027_hasDexSection(cursor)) {
    LOGMSG_RAW(l_DEBUG, "dex files info                :\n");
    for (u4 i = 0; i < numberOfDexFiles; ++i) {
      LOGMSG_RAW(l_DEBUG, "  [%" PRIu32 "] location checksum : %" PRIx32 " (%" PRIu32 ")\n", i,
                 vdex_027_GetLocationChecksum(cursor, i), vdex_027_GetLocationChecksum(cursor, i));
    }
  }
  LOGMSG_RAW(l_DEBUG, "---- EOF Vdex Header Info ----\n");
}

const u1 *vdex_027_GetNextDexFileData(const u1 *vdexCursor, u4 *curDexEndOff) {
  if (*curDexEndOff == 0) {
    if (vdex_027_hasDexSection(vdexCursor)) {
      // dex[0]
      const u1 *dexBuf = vdex_027_DexBegin(vdexCursor);
      LOGMSG(l_DEBUG, "Processing first Dex file at offset:0x%x", dexBuf - vdexCursor);

      // Adjust curDexEndOff to point at the end of the current Dex
      *curDexEndOff = dexBuf - vdexCursor + dex_getFileSize(dexBuf);

      return dexBuf;
    } else {
      LOGMSG(l_ERROR, "Vdex file has no Dex entries to process");
      return NULL;
    }
  } else {
    // dex[i]
    const u1 *dexBuf = vdexCursor + *curDexEndOff;

    // Dex files are required to be 4 byte aligned
    // dexBuf = (u1*)utils_allignUp((uintptr_t)dexBuf, 4); // TODO: We shouldn't need to repair
    if ((uintptr_t)dexBuf & 0x3) {
      LOGMSG(l_ERROR, "Dex file in offset '0x%x' is not 4 byte aligned", *curDexEndOff);
      return NULL;
    }

    // Check boundaries
    const u1 *dexBufMax = dexBuf + dex_getFileSize(dexBuf);
    if (dexBufMax == vdex_027_DexEnd(vdexCursor)) {
      LOGMSG(l_DEBUG, "Processing last Dex file at offset:0x%x", *curDexEndOff);
    } else if (dexBufMax < vdex_027_DexEnd(vdexCursor)) {
      LOGMSG(l_DEBUG, "Processing Dex file at offset:0x%x", *curDexEndOff);
    } else {
      LOGMSG(l_ERROR, "Invalid cursor offset '0x%x'", *curDexEndOff);
      return NULL;
    }

    // Adjust curDexEndOff to point at the end of the current Dex
    *curDexEndOff += dex_getFileSize(dexBuf);

    return dexBuf;
  }
}

bool vdex_027_SanityCheck(const u1 *cursor, size_t bufSz) {
  // Check that verifier deps section doesn't point past the end of file. We expect at least one
  // byte (the number of entries) per struct.
  const vdexSectionHeader_027 *pDepsSectHeader = vdex_027_GetSectionHeader(cursor,
                                                                           kVerifierDepsSection);
  if (pDepsSectHeader->sectionOffset && pDepsSectHeader->sectionSize &&
      ((pDepsSectHeader->sectionOffset + 7) > bufSz)) {
    LOGMSG(l_ERROR,
           "Verifier dependencies section points past the end of file (%" PRIx32 " + %" PRIx32
           " > %" PRIx32 ")",
           pDepsSectHeader->sectionOffset, pDepsSectHeader->sectionSize, bufSz);
    return false;
  }

  return true;
}

int vdex_027_process(const char *VdexFileName,
                     const u1 *cursor,
                     size_t bufSz,
                     const runArgs_t *pRunArgs) {
  // Update Dex disassembler engine status
  dex_setDisassemblerStatus(pRunArgs->enableDisassembler);

  // Measure time spend to process all Dex files of a Vdex file
  struct timespec timer;
  utils_startTimer(&timer);

  // Process Vdex file
  int ret = vdex_backend_027_process(VdexFileName, cursor, bufSz, pRunArgs);

  // Get elapsed time in ns
  long timeSpend = utils_endTimer(&timer);
  LOGMSG(l_DEBUG, "Took %ld ms to process Vdex file", timeSpend / 1000000);

  return ret;
}

void vdex_027_dumpDepsInfo(const u1 *vdexFileBuf) { vdex_backend_027_dumpDepsInfo(vdexFileBuf); }
