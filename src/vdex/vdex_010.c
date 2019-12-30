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

#include "vdex_010.h"

#include "../out_writer.h"
#include "../utils.h"
#include "vdex_backend_010.h"

bool vdex_010_isMagicValid(const u1 *cursor) {
  const vdexHeader_010 *pVdexHeader = (const vdexHeader_010 *)cursor;
  return (memcmp(pVdexHeader->magic, kVdexMagic, sizeof(kVdexMagic)) == 0);
}

bool vdex_010_isVersionValid(const u1 *cursor) {
  const vdexHeader_010 *pVdexHeader = (const vdexHeader_010 *)cursor;
  return (memcmp(pVdexHeader->version, kVdex010, sizeof(kVdex010)) == 0);
}

bool vdex_010_isValidVdex(const u1 *cursor) {
  return vdex_010_isMagicValid(cursor) && vdex_010_isVersionValid(cursor);
}

bool vdex_010_hasDexSection(const u1 *cursor) {
  const vdexHeader_010 *pVdexHeader = (const vdexHeader_010 *)cursor;
  return pVdexHeader->dexSize != 0;
}

u4 vdex_010_GetSizeOfChecksumsSection(const u1 *cursor) {
  const vdexHeader_010 *pVdexHeader = (const vdexHeader_010 *)cursor;
  return sizeof(VdexChecksum) * pVdexHeader->numberOfDexFiles;
}

const u1 *vdex_010_DexBegin(const u1 *cursor) {
  return cursor + sizeof(vdexHeader_010) + vdex_010_GetSizeOfChecksumsSection(cursor);
}

u4 vdex_010_DexBeginOffset(const u1 *cursor) {
  return sizeof(vdexHeader_010) + vdex_010_GetSizeOfChecksumsSection(cursor);
}

const u1 *vdex_010_DexEnd(const u1 *cursor) {
  const vdexHeader_010 *pVdexHeader = (const vdexHeader_010 *)cursor;
  return vdex_010_DexBegin(cursor) + pVdexHeader->dexSize;
}

u4 vdex_010_DexEndOffset(const u1 *cursor) {
  const vdexHeader_010 *pVdexHeader = (const vdexHeader_010 *)cursor;
  return vdex_010_DexBeginOffset(cursor) + pVdexHeader->dexSize;
}

const u1 *vdex_010_GetNextDexFileData(const u1 *cursor, u4 *curOffset) {
  if (*curOffset == 0) {
    if (vdex_010_hasDexSection(cursor)) {
      const u1 *dexBuf = vdex_010_DexBegin(cursor);
      *curOffset = sizeof(vdexHeader_010) + vdex_010_GetSizeOfChecksumsSection(cursor);
      LOGMSG(l_DEBUG, "Processing first Dex file at offset:0x%x", *curOffset);

      // Adjust offset to point at the end of current Dex file
      *curOffset += dex_getFileSize(dexBuf);
      return dexBuf;
    } else {
      LOGMSG(l_ERROR, "Vdex file has no Dex entries to process");
      return NULL;
    }
  } else {
    // Check boundaries
    const u1 *dexBuf = cursor + *curOffset;
    const u1 *dexBufMax = dexBuf + dex_getFileSize(dexBuf);
    if (dexBufMax == vdex_010_DexEnd(cursor)) {
      LOGMSG(l_DEBUG, "Processing last Dex file at offset:0x%x", *curOffset);
    } else if (dexBufMax < vdex_010_DexEnd(cursor)) {
      LOGMSG(l_DEBUG, "Processing Dex file at offset:0x%x", *curOffset);
    } else {
      LOGMSG(l_ERROR, "Invalid cursor offset '0x%x'", *curOffset);
      return NULL;
    }

    // Adjust curOffset to point at the end of current Dex file
    *curOffset += dex_getFileSize(dexBuf);
    return dexBuf;
  }
}

u4 vdex_010_GetLocationChecksum(const u1 *cursor, u4 fileIdx) {
  u4 *checksums = (u4 *)(cursor + sizeof(vdexHeader_010));
  return checksums[fileIdx];
}

void vdex_010_SetLocationChecksum(const u1 *cursor, u4 fileIdx, u4 value) {
  u4 *checksums = (u4 *)(cursor + sizeof(vdexHeader_010));
  checksums[fileIdx] = value;
}

void vdex_010_GetVerifierDeps(const u1 *cursor, vdex_data_array_t *pVerifierDeps) {
  const vdexHeader_010 *pVdexHeader = (const vdexHeader_010 *)cursor;
  pVerifierDeps->data = vdex_010_DexBegin(cursor) + pVdexHeader->dexSize;
  pVerifierDeps->offset = vdex_010_DexBeginOffset(cursor) + pVdexHeader->dexSize;
  pVerifierDeps->size = pVdexHeader->verifierDepsSize;
}

void vdex_010_GetQuickeningInfo(const u1 *cursor, vdex_data_array_t *pQuickInfo) {
  vdex_data_array_t vDeps;
  vdex_010_GetVerifierDeps(cursor, &vDeps);
  const vdexHeader_010 *pVdexHeader = (const vdexHeader_010 *)cursor;
  pQuickInfo->data = vDeps.data + pVdexHeader->verifierDepsSize;
  pQuickInfo->offset = vDeps.offset + pVdexHeader->verifierDepsSize;
  pQuickInfo->size = pVdexHeader->quickeningInfoSize;
}

void vdex_010_dumpHeaderInfo(const u1 *cursor) {
  const vdexHeader_010 *pVdexHeader = (const vdexHeader_010 *)cursor;
  vdex_data_array_t vDeps;
  vdex_010_GetVerifierDeps(cursor, &vDeps);
  vdex_data_array_t quickInfo;
  vdex_010_GetQuickeningInfo(cursor, &quickInfo);

  LOGMSG_RAW(l_DEBUG, "------ Vdex Header Info ------\n");
  LOGMSG_RAW(l_DEBUG, "magic header & version      : %.4s-%.4s\n", pVdexHeader->magic,
             pVdexHeader->version);
  LOGMSG_RAW(l_DEBUG, "number of dex files         : %" PRIx32 " (%" PRIu32 ")\n",
             pVdexHeader->numberOfDexFiles, pVdexHeader->numberOfDexFiles);
  LOGMSG_RAW(l_DEBUG, "dex size (overall)          : %" PRIx32 " (%" PRIu32 ")\n",
             pVdexHeader->dexSize, pVdexHeader->dexSize);
  LOGMSG_RAW(l_DEBUG, "verifier dependencies size  : %" PRIx32 " (%" PRIu32 ")\n", vDeps.size,
             vDeps.size);
  LOGMSG_RAW(l_DEBUG, "verifier dependencies offset: %" PRIx32 " (%" PRIu32 ")\n", vDeps.offset,
             vDeps.offset);
  LOGMSG_RAW(l_DEBUG, "quickening info size        : %" PRIx32 " (%" PRIu32 ")\n", quickInfo.size,
             quickInfo.size);
  LOGMSG_RAW(l_DEBUG, "quickening info offset      : %" PRIx32 " (%" PRIu32 ")\n", quickInfo.offset,
             quickInfo.offset);
  LOGMSG_RAW(l_DEBUG, "dex files info              :\n");

  for (u4 i = 0; i < pVdexHeader->numberOfDexFiles; ++i) {
    LOGMSG_RAW(l_DEBUG, "  [%" PRIu32 "] location checksum : %" PRIx32 " (%" PRIu32 ")\n", i,
               vdex_010_GetLocationChecksum(cursor, i), vdex_010_GetLocationChecksum(cursor, i));
  }
  LOGMSG_RAW(l_DEBUG, "---- EOF Vdex Header Info ----\n");
}

bool vdex_010_SanityCheck(const u1 *cursor, size_t bufSz) {
  // Check that verifier deps section doesn't point past the end of file. We expect at least one
  // byte (the number of entries) per struct.
  vdex_data_array_t vDeps;
  vdex_010_GetVerifierDeps(cursor, &vDeps);
  if (vDeps.offset && vDeps.size && ((vDeps.offset + 7) > bufSz)) {
    LOGMSG(l_ERROR,
           "Verifier dependencies section points past the end of file (%" PRIx32 " + %" PRIx32
           " > %" PRIx32 ")",
           vDeps.offset, vDeps.size, bufSz);
    return false;
  }

  // Check that quickening info section doesn't point past the end of file
  vdex_data_array_t quickInfo;
  vdex_010_GetQuickeningInfo(cursor, &quickInfo);
  if (quickInfo.size && ((quickInfo.offset + quickInfo.size) > bufSz)) {
    LOGMSG(l_ERROR,
           "Quickening info section points past the end of file (%" PRIx32 " + %" PRIx32
           " > %" PRIx32 ")",
           quickInfo.offset, quickInfo.size, bufSz);
    return false;
  }
  return true;
}

int vdex_010_process(const char *VdexFileName,
                     const u1 *cursor,
                     size_t bufSz,
                     const runArgs_t *pRunArgs) {
  // Update Dex disassembler engine status
  dex_setDisassemblerStatus(pRunArgs->enableDisassembler);

  // Measure time spend to process all Dex files of a Vdex file
  struct timespec timer;
  utils_startTimer(&timer);

  // Process Vdex file
  int ret = vdex_backend_010_process(VdexFileName, cursor, bufSz, pRunArgs);

  // Get elapsed time in ns
  long timeSpend = utils_endTimer(&timer);
  LOGMSG(l_DEBUG, "Took %ld ms to process Vdex file", timeSpend / 1000000);

  return ret;
}

void vdex_010_dumpDepsInfo(const u1 *vdexFileBuf) { vdex_backend_010_dumpDepsInfo(vdexFileBuf); }
