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

#include "vdex_021.h"

#include "../out_writer.h"
#include "../utils.h"
#include "vdex_backend_021.h"

bool vdex_021_isMagicValid(const u1 *cursor) {
  const vdexHeader_021 *pVdexHeader = (const vdexHeader_021 *)cursor;
  return (memcmp(pVdexHeader->magic, kVdexMagic, sizeof(kVdexMagic)) == 0);
}

bool vdex_021_IsVerifierDepsVersionValid(const u1 *cursor) {
  const vdexHeader_021 *pVdexHeader = (const vdexHeader_021 *)cursor;
  return (memcmp(pVdexHeader->verifierDepsVersion, kVdexDepsVer_021, sizeof(kVdexDepsVer_021)) ==
          0);
}

bool vdex_021_IsDexSectionVersionValid(const u1 *cursor) {
  const vdexHeader_021 *pVdexHeader = (const vdexHeader_021 *)cursor;
  return (memcmp(pVdexHeader->dexSectionVersion, kVdexDexSectVer_021,
                 sizeof(kVdexDexSectVer_021)) == 0) ||
         (memcmp(pVdexHeader->dexSectionVersion, kDexSectVerEmpty_021,
                 sizeof(kDexSectVerEmpty_021)) == 0);
}

bool vdex_021_isValidVdex(const u1 *cursor) {
  return vdex_021_isMagicValid(cursor) && vdex_021_IsVerifierDepsVersionValid(cursor) &&
         vdex_021_IsDexSectionVersionValid(cursor);
}

bool vdex_021_hasDexSection(const u1 *cursor) {
  const vdexHeader_021 *pVdexHeader = (const vdexHeader_021 *)cursor;
  return (memcmp(pVdexHeader->dexSectionVersion, kVdexDexSectVer_021,
                 sizeof(kVdexDexSectVer_021)) == 0);
}

u4 vdex_021_GetSizeOfChecksumsSection(const u1 *cursor) {
  const vdexHeader_021 *pVdexHeader = (const vdexHeader_021 *)cursor;
  return sizeof(VdexChecksum) * pVdexHeader->numberOfDexFiles;
}

u4 vdex_021_GetDexSectionHeaderOffset(const u1 *cursor) {
  return sizeof(vdexHeader_021) + vdex_021_GetSizeOfChecksumsSection(cursor);
}

const vdexDexSectHeader_021 *vdex_021_GetDexSectionHeader(const u1 *cursor) {
  CHECK(vdex_021_hasDexSection(cursor));
  return (vdexDexSectHeader_021 *)(cursor + vdex_021_GetDexSectionHeaderOffset(cursor));
}

const u1 *vdex_021_DexBegin(const u1 *cursor) {
  CHECK(vdex_021_hasDexSection(cursor));
  return cursor + vdex_021_GetDexSectionHeaderOffset(cursor) + sizeof(vdexDexSectHeader_021);
}

u4 vdex_021_DexBeginOffset(const u1 *cursor) {
  CHECK(vdex_021_hasDexSection(cursor));
  return vdex_021_GetDexSectionHeaderOffset(cursor) + sizeof(vdexDexSectHeader_021);
}

const u1 *vdex_021_DexEnd(const u1 *cursor) {
  CHECK(vdex_021_hasDexSection(cursor));
  const vdexDexSectHeader_021 *pDexSectHeader = vdex_021_GetDexSectionHeader(cursor);
  return vdex_021_DexBegin(cursor) + pDexSectHeader->dexSize;
}

u4 vdex_021_DexEndOffset(const u1 *cursor) {
  CHECK(vdex_021_hasDexSection(cursor));
  const vdexDexSectHeader_021 *pDexSectHeader = vdex_021_GetDexSectionHeader(cursor);
  return vdex_021_DexBeginOffset(cursor) + pDexSectHeader->dexSize;
}

u4 vdex_021_GetLocationChecksum(const u1 *cursor, u4 fileIdx) {
  const vdexHeader_021 *pVdexHeader = (const vdexHeader_021 *)cursor;
  CHECK_LT(fileIdx, pVdexHeader->numberOfDexFiles);
  u4 *checksums = (u4 *)(cursor + sizeof(vdexHeader_021));
  return checksums[fileIdx];
}

void vdex_021_SetLocationChecksum(const u1 *cursor, u4 fileIdx, u4 value) {
  const vdexHeader_021 *pVdexHeader = (const vdexHeader_021 *)cursor;
  CHECK_LT(fileIdx, pVdexHeader->numberOfDexFiles);
  u4 *checksums = (u4 *)(cursor + sizeof(vdexHeader_021));
  checksums[fileIdx] = value;
}

u4 vdex_021_GetVerifierDepsStartOffset(const u1 *cursor) {
  u4 result = vdex_021_GetDexSectionHeaderOffset(cursor);
  if (vdex_021_hasDexSection(cursor)) {
    // When there is a dex section, the verifier deps are after it, but before the quickening.
    const vdexDexSectHeader_021 *pDexSectHeader = vdex_021_GetDexSectionHeader(cursor);
    return result + sizeof(vdexDexSectHeader_021) + pDexSectHeader->dexSize +
           pDexSectHeader->dexSharedDataSize;
  } else {
    // When there is no dex section, the verifier deps are just after the header.
    return result;
  }
}

void vdex_021_GetVerifierDeps(const u1 *cursor, vdex_data_array_t *pVerifierDeps) {
  pVerifierDeps->offset = vdex_021_GetVerifierDepsStartOffset(cursor);
  pVerifierDeps->data = cursor + pVerifierDeps->offset;
  const vdexHeader_021 *pVdexHeader = (const vdexHeader_021 *)cursor;
  pVerifierDeps->size = pVdexHeader->verifierDepsSize;
}

void vdex_021_GetQuickeningInfo(const u1 *cursor, vdex_data_array_t *pQuickInfo) {
  if (vdex_021_hasDexSection(cursor)) {
    vdex_data_array_t vDeps;
    vdex_021_GetVerifierDeps(cursor, &vDeps);
    pQuickInfo->data = vDeps.data + vDeps.size;
    pQuickInfo->offset = vDeps.offset + vDeps.size;
    const vdexDexSectHeader_021 *pDexSectHeader = vdex_021_GetDexSectionHeader(cursor);
    pQuickInfo->size = pDexSectHeader->quickeningInfoSize;
  } else {
    pQuickInfo->data = NULL;
    pQuickInfo->offset = -1;
    pQuickInfo->size = 0;
  }
}

void vdex_021_GetBootClassPathChecksumData(const u1 *cursor, vdex_data_array_t *pBootClsPathCsums) {
  const vdexHeader_021 *pVdexHeader = (const vdexHeader_021 *)cursor;
  pBootClsPathCsums->size = pVdexHeader->bootclasspathChecksumsSize;

  // If not present don't bother process offsets
  if (pBootClsPathCsums->size == 0) {
    pBootClsPathCsums->data = NULL;
    pBootClsPathCsums->offset = -1;
    return;
  }

  vdex_data_array_t vQuickInfo;
  vdex_021_GetVerifierDeps(cursor, &vQuickInfo);
  if (vQuickInfo.size) {
    // if QuickInfo present BootClassPathChecksumData are following
    pBootClsPathCsums->data = vQuickInfo.data + vQuickInfo.size;
    pBootClsPathCsums->offset = vQuickInfo.offset + vQuickInfo.size;
  } else {
    // Otherwise the are under VerifierDependencies
    vdex_data_array_t vDeps;
    vdex_021_GetVerifierDeps(cursor, &vDeps);
    pBootClsPathCsums->data = vDeps.data + vDeps.size;
    pBootClsPathCsums->offset = vDeps.offset + vDeps.size;
  }
}

void vdex_021_GetClassLoaderContextData(const u1 *cursor, vdex_data_array_t *pClsLoaderCtx) {
  const vdexHeader_021 *pVdexHeader = (const vdexHeader_021 *)cursor;
  pClsLoaderCtx->size = pVdexHeader->bootclasspathChecksumsSize;

  // If not present don't bother process offsets
  if (pClsLoaderCtx->size == 0) {
    pClsLoaderCtx->data = NULL;
    pClsLoaderCtx->offset = -1;
    return;
  }

  vdex_data_array_t bootClsPathCsums;
  vdex_021_GetBootClassPathChecksumData(cursor, &bootClsPathCsums);
  pClsLoaderCtx->data = bootClsPathCsums.data + bootClsPathCsums.size;
  pClsLoaderCtx->offset = bootClsPathCsums.offset + bootClsPathCsums.size;
}

void vdex_021_GetQuickenInfoOffsetTable(const u1 *dexBuf,
                                        const vdex_data_array_t *pQuickInfo,
                                        vdex_data_array_t *pOffTable) {
  // The offset is in preheader right before the beginning of the Dex file
  const u4 offset = ((u4 *)dexBuf)[-1];
  CHECK_LE(offset, pQuickInfo->size);

  pOffTable->size = pQuickInfo->size - offset;
  pOffTable->data = pQuickInfo->data + offset;
  pOffTable->offset = pQuickInfo->offset + offset;
}

void vdex_021_dumpHeaderInfo(const u1 *cursor) {
  const vdexHeader_021 *pVdexHeader = (const vdexHeader_021 *)cursor;
  vdex_data_array_t vDeps;
  vdex_021_GetVerifierDeps(cursor, &vDeps);
  vdex_data_array_t quickInfo;
  vdex_021_GetQuickeningInfo(cursor, &quickInfo);
  vdex_data_array_t bootClsPathCsums;
  vdex_021_GetBootClassPathChecksumData(cursor, &bootClsPathCsums);
  vdex_data_array_t clsLoaderCtx;
  vdex_021_GetClassLoaderContextData(cursor, &clsLoaderCtx);

  LOGMSG_RAW(l_DEBUG, "------ Vdex Header Info -------\n");
  LOGMSG_RAW(l_DEBUG, "magic header                  : %.4s\n", pVdexHeader->magic);
  LOGMSG_RAW(l_DEBUG, "verifier dependencies version : %.4s\n", pVdexHeader->verifierDepsVersion);
  LOGMSG_RAW(l_DEBUG, "dex section version           : %.4s\n", pVdexHeader->dexSectionVersion);
  LOGMSG_RAW(l_DEBUG, "number of dex files           : %" PRIx32 " (%" PRIu32 ")\n",
             pVdexHeader->numberOfDexFiles, pVdexHeader->numberOfDexFiles);
  LOGMSG_RAW(l_DEBUG, "verifier dependencies size    : %" PRIx32 " (%" PRIu32 ")\n", vDeps.size,
             vDeps.size);
  LOGMSG_RAW(l_DEBUG, "verifier dependencies offset  : %" PRIx32 " (%" PRIu32 ")\n", vDeps.offset,
             vDeps.offset);
  LOGMSG_RAW(l_DEBUG, "quickening info size          : %" PRIx32 " (%" PRIu32 ")\n", quickInfo.size,
             quickInfo.size);
  LOGMSG_RAW(l_DEBUG, "quickening info offset        : %" PRIx32 " (%" PRIu32 ")\n",
             quickInfo.offset, quickInfo.offset);
  LOGMSG_RAW(l_DEBUG, "boot clspath checksums size   : %" PRIx32 " (%" PRIu32 ")\n",
             bootClsPathCsums.size, bootClsPathCsums.size);
  LOGMSG_RAW(l_DEBUG, "boot clspath checksums offset : %" PRIx32 " (%" PRIu32 ")\n",
             bootClsPathCsums.offset, bootClsPathCsums.offset);
  LOGMSG_RAW(l_DEBUG, "class loader context size     : %" PRIx32 " (%" PRIu32 ")\n",
             clsLoaderCtx.size, clsLoaderCtx.size);
  LOGMSG_RAW(l_DEBUG, "class loader context offset   : %" PRIx32 " (%" PRIu32 ")\n",
             clsLoaderCtx.offset, clsLoaderCtx.offset);
  if (vdex_021_hasDexSection(cursor)) {
    const vdexDexSectHeader_021 *pDexSectHeader = vdex_021_GetDexSectionHeader(cursor);
    LOGMSG_RAW(l_DEBUG, "dex section header offset     : %" PRIx32 " (%" PRIu32 ")\n",
               vdex_021_GetDexSectionHeaderOffset(cursor),
               vdex_021_GetDexSectionHeaderOffset(cursor));
    LOGMSG_RAW(l_DEBUG, "dex size                      : %" PRIx32 " (%" PRIu32 ")\n",
               pDexSectHeader->dexSize, pDexSectHeader->dexSize);
    LOGMSG_RAW(l_DEBUG, "dex shared data size          : %" PRIx32 " (%" PRIu32 ")\n",
               pDexSectHeader->dexSharedDataSize, pDexSectHeader->dexSharedDataSize);
    LOGMSG_RAW(l_DEBUG, "dex files info                :\n");
    for (u4 i = 0; i < pVdexHeader->numberOfDexFiles; ++i) {
      LOGMSG_RAW(l_DEBUG, "  [%" PRIu32 "] location checksum : %" PRIx32 " (%" PRIu32 ")\n", i,
                 vdex_021_GetLocationChecksum(cursor, i), vdex_021_GetLocationChecksum(cursor, i));
    }
  }
  LOGMSG_RAW(l_DEBUG, "---- EOF Vdex Header Info ----\n");
}

const u1 *vdex_021_GetNextDexFileData(const u1 *vdexCursor, u4 *curDexEndOff) {
  if (*curDexEndOff == 0) {
    if (vdex_021_hasDexSection(vdexCursor)) {
      // quicken_table_off[0] + dex[0]
      const u1 *begin = vdex_021_DexBegin(vdexCursor);
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
    if (dexBufMax == vdex_021_DexEnd(vdexCursor)) {
      LOGMSG(l_DEBUG, "Processing last Dex file at offset:0x%x", *curDexEndOff);
    } else if (dexBufMax < vdex_021_DexEnd(vdexCursor)) {
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

bool vdex_021_SanityCheck(const u1 *cursor, size_t bufSz) {
  // Check that verifier deps section doesn't point past the end of file. We expect at least one
  // byte (the number of entries) per struct.
  vdex_data_array_t vDeps;
  vdex_021_GetVerifierDeps(cursor, &vDeps);
  if (vDeps.offset && vDeps.size && ((vDeps.offset + 7) > bufSz)) {
    LOGMSG(l_ERROR,
           "Verifier dependencies section points past the end of file (%" PRIx32 " + %" PRIx32
           " > %" PRIx32 ")",
           vDeps.offset, vDeps.size, bufSz);
    return false;
  }

  // Check that quickening info section doesn't point past the end of file
  vdex_data_array_t quickInfo;
  vdex_021_GetQuickeningInfo(cursor, &quickInfo);
  if (quickInfo.size && ((quickInfo.offset + quickInfo.size) > bufSz)) {
    LOGMSG(l_ERROR,
           "Quickening info section points past the end of file (%" PRIx32 " + %" PRIx32
           " > %" PRIx32 ")",
           quickInfo.offset, quickInfo.size, bufSz);
    return false;
  }

  // Check that BootClassPathChecksum doesn't point past the end of file
  vdex_data_array_t bootClsPathCsums;
  vdex_021_GetBootClassPathChecksumData(cursor, &bootClsPathCsums);
  if (bootClsPathCsums.size && ((bootClsPathCsums.offset + bootClsPathCsums.size) > bufSz)) {
    LOGMSG(l_ERROR,
           "BootClassPathChecksum section points past the end of file (%" PRIx32 " + %" PRIx32
           " > %" PRIx32 ")",
           bootClsPathCsums.offset, bootClsPathCsums.size, bufSz);
    return false;
  }

  // Check that ClassLoaderContextData doesn't point past the end of file
  vdex_data_array_t clsLoaderCtx;
  vdex_021_GetClassLoaderContextData(cursor, &clsLoaderCtx);
  if (clsLoaderCtx.size && ((clsLoaderCtx.offset + clsLoaderCtx.size) > bufSz)) {
    LOGMSG(l_ERROR,
           "ClassLoaderContext section points past the end of file (%" PRIx32 " + %" PRIx32
           " > %" PRIx32 ")",
           clsLoaderCtx.offset, clsLoaderCtx.size, bufSz);
    return false;
  }

  return true;
}

int vdex_021_process(const char *VdexFileName,
                     const u1 *cursor,
                     size_t bufSz,
                     const runArgs_t *pRunArgs) {
  // Update Dex disassembler engine status
  dex_setDisassemblerStatus(pRunArgs->enableDisassembler);

  // Measure time spend to process all Dex files of a Vdex file
  struct timespec timer;
  utils_startTimer(&timer);

  // Process Vdex file
  int ret = vdex_backend_021_process(VdexFileName, cursor, bufSz, pRunArgs);

  // Get elapsed time in ns
  long timeSpend = utils_endTimer(&timer);
  LOGMSG(l_DEBUG, "Took %ld ms to process Vdex file", timeSpend / 1000000);

  return ret;
}

void vdex_021_dumpDepsInfo(const u1 *vdexFileBuf) { vdex_backend_021_dumpDepsInfo(vdexFileBuf); }
