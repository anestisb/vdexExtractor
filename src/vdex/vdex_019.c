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

#include "vdex_019.h"
#include "../out_writer.h"
#include "../utils.h"
#include "vdex_backend_019.h"

bool vdex_019_isMagicValid(const u1 *cursor) {
  const vdexHeader_019 *pVdexHeader = (const vdexHeader_019 *)cursor;
  return (memcmp(pVdexHeader->magic, kVdexMagic, sizeof(kVdexMagic)) == 0);
}

bool vdex_019_IsVerifierDepsVersionValid(const u1 *cursor) {
  const vdexHeader_019 *pVdexHeader = (const vdexHeader_019 *)cursor;
  return (memcmp(pVdexHeader->verifierDepsVersion, kVdexDepsVer, sizeof(kVdexDepsVer)) == 0);
}

bool vdex_019_IsDexSectionVersionValid(const u1 *cursor) {
  const vdexHeader_019 *pVdexHeader = (const vdexHeader_019 *)cursor;
  return (memcmp(pVdexHeader->dexSectionVersion, kVdexDexSectVer, sizeof(kVdexDexSectVer)) == 0) ||
         (memcmp(pVdexHeader->dexSectionVersion, kDexSectVerEmpty, sizeof(kDexSectVerEmpty)) == 0);
}

bool vdex_019_isValidVdex(const u1 *cursor) {
  return vdex_019_isMagicValid(cursor) && vdex_019_IsVerifierDepsVersionValid(cursor) &&
         vdex_019_IsDexSectionVersionValid(cursor);
}

bool vdex_019_hasDexSection(const u1 *cursor) {
  const vdexHeader_019 *pVdexHeader = (const vdexHeader_019 *)cursor;
  return (memcmp(pVdexHeader->dexSectionVersion, kVdexDexSectVer, sizeof(kVdexDexSectVer)) == 0);
}

u4 vdex_019_GetSizeOfChecksumsSection(const u1 *cursor) {
  const vdexHeader_019 *pVdexHeader = (const vdexHeader_019 *)cursor;
  return sizeof(VdexChecksum) * pVdexHeader->numberOfDexFiles;
}

u4 vdex_019_GetDexSectionHeaderOffset(const u1 *cursor) {
  return sizeof(vdexHeader_019) + vdex_019_GetSizeOfChecksumsSection(cursor);
}

const DexSectHeader *vdex_019_GetDexSectionHeader(const u1 *cursor) {
  CHECK(vdex_019_hasDexSection(cursor));
  return (DexSectHeader *)(cursor + vdex_019_GetDexSectionHeaderOffset(cursor));
}

const u1 *vdex_019_DexBegin(const u1 *cursor) {
  CHECK(vdex_019_hasDexSection(cursor));
  return cursor + vdex_019_GetDexSectionHeaderOffset(cursor) + sizeof(DexSectHeader);
}

u4 vdex_019_DexBeginOffset(const u1 *cursor) {
  CHECK(vdex_019_hasDexSection(cursor));
  return vdex_019_GetDexSectionHeaderOffset(cursor) + sizeof(DexSectHeader);
}

const u1 *vdex_019_DexEnd(const u1 *cursor) {
  CHECK(vdex_019_hasDexSection(cursor));
  const DexSectHeader *pDexSectHeader = vdex_019_GetDexSectionHeader(cursor);
  return vdex_019_DexBegin(cursor) + pDexSectHeader->dexSize;
}

u4 vdex_019_DexEndOffset(const u1 *cursor) {
  CHECK(vdex_019_hasDexSection(cursor));
  const DexSectHeader *pDexSectHeader = vdex_019_GetDexSectionHeader(cursor);
  return vdex_019_DexBeginOffset(cursor) + pDexSectHeader->dexSize;
}

u4 vdex_019_GetLocationChecksum(const u1 *cursor, u4 fileIdx) {
  const vdexHeader_019 *pVdexHeader = (const vdexHeader_019 *)cursor;
  CHECK_LT(fileIdx, pVdexHeader->numberOfDexFiles);
  u4 *checksums = (u4 *)(cursor + sizeof(vdexHeader_019));
  return checksums[fileIdx];
}

void vdex_019_SetLocationChecksum(const u1 *cursor, u4 fileIdx, u4 value) {
  const vdexHeader_019 *pVdexHeader = (const vdexHeader_019 *)cursor;
  CHECK_LT(fileIdx, pVdexHeader->numberOfDexFiles);
  u4 *checksums = (u4 *)(cursor + sizeof(vdexHeader_019));
  checksums[fileIdx] = value;
}

u4 vdex_019_GetVerifierDepsStartOffset(const u1 *cursor) {
  u4 result = vdex_019_GetDexSectionHeaderOffset(cursor);
  if (vdex_019_hasDexSection(cursor)) {
    // When there is a dex section, the verifier deps are after it, but before the quickening.
    const DexSectHeader *pDexSectHeader = vdex_019_GetDexSectionHeader(cursor);
    return result + sizeof(DexSectHeader) + pDexSectHeader->dexSize +
           pDexSectHeader->dexSharedDataSize;
  } else {
    // When there is no dex section, the verifier deps are just after the header.
    return result;
  }
}

const u1 *vdex_019_GetVerifierDepsData(const u1 *cursor) {
  return cursor + vdex_019_GetVerifierDepsStartOffset(cursor);
}

u4 vdex_019_GetVerifierDepsDataOffset(const u1 *cursor) {
  return vdex_019_GetVerifierDepsStartOffset(cursor);
}

u4 vdex_019_GetVerifierDepsDataSize(const u1 *cursor) {
  const vdexHeader_019 *pVdexHeader = (const vdexHeader_019 *)cursor;
  return pVdexHeader->verifierDepsSize;
}

const u1 *vdex_019_GetQuickeningInfo(const u1 *cursor) {
  if (vdex_019_hasDexSection(cursor)) {
    return vdex_019_GetVerifierDepsData(cursor) + vdex_019_GetVerifierDepsDataSize(cursor);
  } else {
    return NULL;
  }
}

u4 vdex_019_GetQuickeningInfoOffset(const u1 *cursor) {
  if (vdex_019_hasDexSection(cursor)) {
    return vdex_019_GetVerifierDepsDataOffset(cursor) + vdex_019_GetVerifierDepsDataSize(cursor);
  } else {
    return 0;
  }
}

u4 vdex_019_GetQuickeningInfoSize(const u1 *cursor) {
  if (vdex_019_hasDexSection(cursor)) {
    const DexSectHeader *pDexSectHeader = vdex_019_GetDexSectionHeader(cursor);
    return pDexSectHeader->quickeningInfoSize;
  } else {
    return 0;
  }
}

void vdex_019_dumpHeaderInfo(const u1 *cursor) {
  const vdexHeader_019 *pVdexHeader = (const vdexHeader_019 *)cursor;

  LOGMSG_RAW(l_DEBUG, "------ Vdex Header Info -------\n");
  LOGMSG_RAW(l_DEBUG, "magic header                  : %.4s\n", pVdexHeader->magic);
  LOGMSG_RAW(l_DEBUG, "verifier dependencies version : %.4s\n", pVdexHeader->verifierDepsVersion);
  LOGMSG_RAW(l_DEBUG, "dex section version           : %.4s\n", pVdexHeader->dexSectionVersion);
  LOGMSG_RAW(l_DEBUG, "number of dex files           : %" PRIx32 " (%" PRIu32 ")\n",
             pVdexHeader->numberOfDexFiles, pVdexHeader->numberOfDexFiles);
  LOGMSG_RAW(l_DEBUG, "verifier dependencies size    : %" PRIx32 " (%" PRIu32 ")\n",
             vdex_019_GetVerifierDepsDataSize(cursor), vdex_019_GetVerifierDepsDataSize(cursor));
  LOGMSG_RAW(l_DEBUG, "verifier dependencies offset  : %" PRIx32 " (%" PRIu32 ")\n",
             vdex_019_GetVerifierDepsDataOffset(cursor),
             vdex_019_GetVerifierDepsDataOffset(cursor));
  LOGMSG_RAW(l_DEBUG, "quickening info size          : %" PRIx32 " (%" PRIu32 ")\n",
             vdex_019_GetQuickeningInfoSize(cursor), vdex_019_GetQuickeningInfoSize(cursor));
  LOGMSG_RAW(l_DEBUG, "quickening info offset        : %" PRIx32 " (%" PRIu32 ")\n",
             vdex_019_GetQuickeningInfoOffset(cursor), vdex_019_GetQuickeningInfoOffset(cursor));
  if (vdex_019_hasDexSection(cursor)) {
    const DexSectHeader *pDexSectHeader = vdex_019_GetDexSectionHeader(cursor);
    LOGMSG_RAW(l_DEBUG, "dex section header offset     : %" PRIx32 " (%" PRIu32 ")\n",
               vdex_019_GetDexSectionHeaderOffset(cursor),
               vdex_019_GetDexSectionHeaderOffset(cursor));
    LOGMSG_RAW(l_DEBUG, "dex size                      : %" PRIx32 " (%" PRIu32 ")\n",
               pDexSectHeader->dexSize, pDexSectHeader->dexSize);
    LOGMSG_RAW(l_DEBUG, "dex shared data size          : %" PRIx32 " (%" PRIu32 ")\n",
               pDexSectHeader->dexSharedDataSize, pDexSectHeader->dexSharedDataSize);
    LOGMSG_RAW(l_DEBUG, "dex files info                :\n");
    for (u4 i = 0; i < pVdexHeader->numberOfDexFiles; ++i) {
      LOGMSG_RAW(l_DEBUG, "  [%" PRIu32 "] location checksum : %" PRIx32 " (%" PRIu32 ")\n", i,
                 vdex_019_GetLocationChecksum(cursor, i), vdex_019_GetLocationChecksum(cursor, i));
    }
  }
  LOGMSG_RAW(l_DEBUG, "---- EOF Vdex Header Info ----\n");
}

const u1 *vdex_019_GetNextDexFileData(const u1 *vdexCursor, u4 *curDexEndOff) {
  if (*curDexEndOff == 0) {
    if (vdex_019_hasDexSection(vdexCursor)) {
      // quicken_table_off[0] + dex[0]
      const u1 *begin = vdex_019_DexBegin(vdexCursor);
      const u1 *dexBuf = begin + sizeof(QuickeningTableOffsetType);
      LOGMSG(l_DEBUG, "Processing first Dex file at offset:0x%x", dexBuf - vdexCursor);

      // Adjust curDexEndOff to point at the end of the current Dex
      *curDexEndOff = dexBuf - vdexCursor + dex_getFileSize(dexBuf);

      return dexBuf;
    } else {
      LOGMSG(l_ERROR, "Vdex file has no Dex entries to process");
      return NULL;
    }
  } else {
    // quicken_table_off[i] + dex[i]
    const u1 *begin = vdexCursor + *curDexEndOff;

    // Dex files are required to be 4 byte aligned
    // begin = (u1*)utils_allignUp((uintptr_t)begin, 4); // TODO: We shouldn't need to repair
    if ((uintptr_t)begin & 0x3) {
      LOGMSG(l_ERROR, "Dex file in offset '0x%x' is not 4 byte aligned", *curDexEndOff);
      return NULL;
    }

    // Current Dex file
    const u1 *dexBuf = begin + sizeof(QuickeningTableOffsetType);

    // Check boundaries
    const u1 *dexBufMax = dexBuf + dex_getFileSize(dexBuf);
    if (dexBufMax == vdex_019_DexEnd(vdexCursor)) {
      LOGMSG(l_DEBUG, "Processing last Dex file at offset:0x%x", *curDexEndOff);
    } else if (dexBufMax < vdex_019_DexEnd(vdexCursor)) {
      LOGMSG(l_DEBUG, "Processing Dex file at offset:0x%x", *curDexEndOff);
    } else {
      LOGMSG(l_ERROR, "Invalid cursor offset '0x%x'", *curDexEndOff);
      return NULL;
    }

    // Adjust curDexEndOff to point at the end of the current Dex
    *curDexEndOff += dex_getFileSize(dexBuf) + sizeof(QuickeningTableOffsetType);

    return dexBuf;
  }
}

bool vdex_019_SanityCheck(const u1 *cursor, size_t bufSz) {
  // Check that verifier deps section doesn't point past the end of file
  u4 depsOff = vdex_019_GetVerifierDepsDataOffset(cursor);
  u4 depsSz = vdex_019_GetVerifierDepsDataSize(cursor);
  if (depsOff + depsSz > bufSz) {
    LOGMSG(l_ERROR, "Verifier dependencies section points past the end of file (%" PRIx32
                    " + %" PRIx32 " > %" PRIx32 ")",
           depsOff, depsSz, bufSz);
    return false;
  }

  // Check that quickening info section doesn't point past the end of file
  u4 qOff = vdex_019_GetQuickeningInfoOffset(cursor);
  u4 qSz = vdex_019_GetQuickeningInfoSize(cursor);
  if (qOff + qSz > bufSz) {
    LOGMSG(l_ERROR, "Quickening info section points past the end of file (%" PRIx32 " + %" PRIx32
                    " > %" PRIx32 ")",
           qOff, qSz, bufSz);
    return false;
  }
  return true;
}

int vdex_019_process(const char *VdexFileName,
                     const u1 *cursor,
                     size_t bufSz,
                     const runArgs_t *pRunArgs) {
  // Update Dex disassembler engine status
  dex_setDisassemblerStatus(pRunArgs->enableDisassembler);

  // Measure time spend to process all Dex files of a Vdex file
  struct timespec timer;
  utils_startTimer(&timer);

  // Process Vdex file
  int ret = vdex_backend_019_process(VdexFileName, cursor, bufSz, pRunArgs);

  // Get elapsed time in ns
  long timeSpend = utils_endTimer(&timer);
  LOGMSG(l_DEBUG, "Took %ld ms to process Vdex file", timeSpend / 1000000);

  return ret;
}

void vdex_019_dumpDepsInfo(const u1 *vdexFileBuf) { vdex_backend_019_dumpDepsInfo(vdexFileBuf); }
