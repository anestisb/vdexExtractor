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

static u2 kUnresolvedMarker = (u2)(-1);

static inline u4 decodeUint32WithOverflowCheck(const u1 **in, const u1 *end) {
  CHECK_LT(*in, end);
  return dex_readULeb128(in);
}

static void decodeDepStrings(const u1 **in, const u1 *end, vdexDepStrings *depStrings) {
  u4 numOfEntries = decodeUint32WithOverflowCheck(in, end);
  depStrings->strings = utils_calloc(numOfEntries * sizeof(char *));
  depStrings->numberOfStrings = numOfEntries;
  for (u4 i = 0; i < numOfEntries; ++i) {
    CHECK_LT(*in, end);
    const char *stringStart = (const char *)(*in);
    depStrings->strings[i] = stringStart;
    *in += strlen(stringStart) + 1;
  }
}

static void decodeDepTypeSet(const u1 **in, const u1 *end, vdexDepTypeSet *pVdexDepTypeSet) {
  u4 numOfEntries = decodeUint32WithOverflowCheck(in, end);
  pVdexDepTypeSet->pVdexDepSets = utils_malloc(numOfEntries * sizeof(vdexDepSet));
  pVdexDepTypeSet->numberOfEntries = numOfEntries;
  for (u4 i = 0; i < numOfEntries; ++i) {
    pVdexDepTypeSet->pVdexDepSets[i].dstIndex = decodeUint32WithOverflowCheck(in, end);
    pVdexDepTypeSet->pVdexDepSets[i].srcIndex = decodeUint32WithOverflowCheck(in, end);
  }
}

static void decodeDepClasses(const u1 **in,
                             const u1 *end,
                             vdexDepClassResSet *pVdexDepClassResSet) {
  u4 numOfEntries = decodeUint32WithOverflowCheck(in, end);
  pVdexDepClassResSet->pVdexDepClasses = utils_malloc(numOfEntries * sizeof(vdexDepClassRes));
  pVdexDepClassResSet->numberOfEntries = numOfEntries;
  for (u4 i = 0; i < numOfEntries; ++i) {
    pVdexDepClassResSet->pVdexDepClasses[i].typeIdx = decodeUint32WithOverflowCheck(in, end);
    pVdexDepClassResSet->pVdexDepClasses[i].accessFlags = decodeUint32WithOverflowCheck(in, end);
  }
}

static void decodeDepFields(const u1 **in, const u1 *end, vdexDepFieldResSet *pVdexDepFieldResSet) {
  u4 numOfEntries = decodeUint32WithOverflowCheck(in, end);
  pVdexDepFieldResSet->pVdexDepFields = utils_malloc(numOfEntries * sizeof(vdexDepFieldRes));
  pVdexDepFieldResSet->numberOfEntries = numOfEntries;
  for (u4 i = 0; i < pVdexDepFieldResSet->numberOfEntries; ++i) {
    pVdexDepFieldResSet->pVdexDepFields[i].fieldIdx = decodeUint32WithOverflowCheck(in, end);
    pVdexDepFieldResSet->pVdexDepFields[i].accessFlags = decodeUint32WithOverflowCheck(in, end);
    pVdexDepFieldResSet->pVdexDepFields[i].declaringClassIdx =
        decodeUint32WithOverflowCheck(in, end);
  }
}

static void decodeDepMethods(const u1 **in,
                             const u1 *end,
                             vdexDepMethodResSet *pVdexDepMethodResSet) {
  u4 numOfEntries = decodeUint32WithOverflowCheck(in, end);
  pVdexDepMethodResSet->pVdexDepMethods = utils_malloc(numOfEntries * sizeof(vdexDepMethodRes));
  pVdexDepMethodResSet->numberOfEntries = numOfEntries;
  for (u4 i = 0; i < numOfEntries; ++i) {
    pVdexDepMethodResSet->pVdexDepMethods[i].methodIdx = decodeUint32WithOverflowCheck(in, end);
    pVdexDepMethodResSet->pVdexDepMethods[i].accessFlags = decodeUint32WithOverflowCheck(in, end);
    pVdexDepMethodResSet->pVdexDepMethods[i].declaringClassIdx =
        decodeUint32WithOverflowCheck(in, end);
  }
}

static void decodeDepUnvfyClasses(const u1 **in,
                                  const u1 *end,
                                  vdexDepUnvfyClassesSet *pVdexDepUnvfyClassesSet) {
  u4 numOfEntries = decodeUint32WithOverflowCheck(in, end);
  pVdexDepUnvfyClassesSet->pVdexDepUnvfyClasses =
      utils_malloc(numOfEntries * sizeof(vdexDepUnvfyClass));
  pVdexDepUnvfyClassesSet->numberOfEntries = numOfEntries;
  for (u4 i = 0; i < pVdexDepUnvfyClassesSet->numberOfEntries; ++i) {
    pVdexDepUnvfyClassesSet->pVdexDepUnvfyClasses[i].typeIdx =
        decodeUint32WithOverflowCheck(in, end);
  }
}

static const char *getStringFromId(const vdexDepData *pVdexDepData,
                                   u4 stringId,
                                   const u1 *dexFileBuf) {
  const dexHeader *pDexHeader = (const dexHeader *)dexFileBuf;
  vdexDepStrings extraStrings = pVdexDepData->extraStrings;
  u4 numIdsInDex = pDexHeader->stringIdsSize;
  if (stringId < numIdsInDex) {
    return dex_getStringDataByIdx(dexFileBuf, stringId);
  } else {
    // Adjust offset
    stringId -= numIdsInDex;
    CHECK_LT(stringId, extraStrings.numberOfStrings);
    return extraStrings.strings[stringId];
  }
}

static void dumpDepsMethodInfo(const u1 *dexFileBuf,
                               const vdexDepData *pVdexDepData,
                               const vdexDepMethodResSet *pMethods,
                               const char *kind) {
  LOGMSG(l_VDEBUG, " %s method dependencies: number_of_methods=%" PRIu32, kind,
         pMethods->numberOfEntries);
  for (u4 i = 0; i < pMethods->numberOfEntries; ++i) {
    const dexMethodId *pDexMethodId =
        dex_getMethodId(dexFileBuf, pMethods->pVdexDepMethods[i].methodIdx);
    u2 accessFlags = pMethods->pVdexDepMethods[i].accessFlags;
    const char *methodSig = dex_getMethodSignature(dexFileBuf, pDexMethodId);
    LOGMSG_RAW(l_VDEBUG, "   %04" PRIu32 ": '%s'->'%s':'%s' is expected to be ", i,
               dex_getMethodDeclaringClassDescriptor(dexFileBuf, pDexMethodId),
               dex_getMethodName(dexFileBuf, pDexMethodId), methodSig);
    free((void *)methodSig);
    if (accessFlags == kUnresolvedMarker) {
      LOGMSG_RAW(l_VDEBUG, "unresolved\n");
    } else {
      LOGMSG_RAW(
          l_VDEBUG, "in class '%s', have the access flags '%" PRIu16 "', and be of kind '%s'\n",
          getStringFromId(pVdexDepData, pMethods->pVdexDepMethods[i].declaringClassIdx, dexFileBuf),
          accessFlags, kind);
    }
  }
}

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

// TODO: Cache embedded Dex file offsets so that we don't have to parse from scratch when we
// want to iterate over all files.
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
  LOGMSG(l_VDEBUG, "dex size (overall)          : %" PRIx32 " (%" PRIu32 ")", pVdexHeader->dexSize,
         pVdexHeader->dexSize);
  LOGMSG(l_VDEBUG, "verifier dependencies size  : %" PRIx32 " (%" PRIu32 ")",
         vdex_GetVerifierDepsDataSize(cursor), vdex_GetVerifierDepsDataSize(cursor));
  LOGMSG(l_VDEBUG, "verifier dependencies offset: %" PRIx32 " (%" PRIu32 ")",
         vdex_GetVerifierDepsDataOffset(cursor), vdex_GetVerifierDepsDataOffset(cursor));
  LOGMSG(l_VDEBUG, "quickening info size        : %" PRIx32 " (%" PRIu32 ")",
         vdex_GetQuickeningInfoSize(cursor), vdex_GetQuickeningInfoSize(cursor));
  LOGMSG(l_VDEBUG, "quickening info offset      : %" PRIx32 " (%" PRIu32 ")",
         vdex_GetQuickeningInfoOffset(cursor), vdex_GetQuickeningInfoOffset(cursor));
  LOGMSG(l_VDEBUG, "dex files info              :")

  for (u4 i = 0; i < pVdexHeader->numberOfDexFiles; ++i) {
    LOGMSG(l_VDEBUG, "  [%" PRIu32 "] location checksum : %" PRIx32 " (%" PRIu32 ")", i,
           vdex_GetLocationChecksum(cursor, i), vdex_GetLocationChecksum(cursor, i));
  }
  LOGMSG(l_VDEBUG, "---- EOF Vdex Header Info ----");
}

vdexDeps *vdex_initDepsInfo(const u1 *vdexFileBuf) {
  if (vdex_GetVerifierDepsDataSize(vdexFileBuf) == 0) {
    // Return eagerly, as the first thing we expect from VerifierDeps data is
    // the number of created strings, even if there is no dependency.
    return NULL;
  }

  vdexDeps *pVdexDeps = utils_malloc(sizeof(vdexDeps));

  const vdexHeader *pVdexHeader = (const vdexHeader *)vdexFileBuf;
  pVdexDeps->numberOfDexFiles = pVdexHeader->numberOfDexFiles;
  pVdexDeps->pVdexDepData = utils_malloc(sizeof(vdexDepData) * pVdexDeps->numberOfDexFiles);

  const u1 *dexFileBuf = NULL;
  u4 offset = 0;

  const u1 *depsDataStart = vdex_GetVerifierDepsData(vdexFileBuf);
  const u1 *depsDataEnd = depsDataStart + vdex_GetVerifierDepsDataSize(vdexFileBuf);

  for (u4 i = 0; i < pVdexDeps->numberOfDexFiles; ++i) {
    dexFileBuf = vdex_GetNextDexFileData(vdexFileBuf, &offset);
    if (dexFileBuf == NULL) {
      LOGMSG(l_FATAL, "Failed to extract Dex file buffer from loaded Vdex");
    }

    // Process encoded extra strings
    decodeDepStrings(&depsDataStart, depsDataEnd, &pVdexDeps->pVdexDepData[i].extraStrings);

    // Process encoded assignable types
    decodeDepTypeSet(&depsDataStart, depsDataEnd, &pVdexDeps->pVdexDepData[i].assignTypeSets);

    // Process encoded unassignable types
    decodeDepTypeSet(&depsDataStart, depsDataEnd, &pVdexDeps->pVdexDepData[i].unassignTypeSets);

    // Process encoded classes
    decodeDepClasses(&depsDataStart, depsDataEnd, &pVdexDeps->pVdexDepData[i].classes);

    // Process encoded fields
    decodeDepFields(&depsDataStart, depsDataEnd, &pVdexDeps->pVdexDepData[i].fields);

    // Process encoded direct_methods
    decodeDepMethods(&depsDataStart, depsDataEnd, &pVdexDeps->pVdexDepData[i].directMethods);

    // Process encoded virtual_methods
    decodeDepMethods(&depsDataStart, depsDataEnd, &pVdexDeps->pVdexDepData[i].virtualMethods);

    // Process encoded interface_methods
    decodeDepMethods(&depsDataStart, depsDataEnd, &pVdexDeps->pVdexDepData[i].interfaceMethods);

    // Process encoded unverified classes
    decodeDepUnvfyClasses(&depsDataStart, depsDataEnd, &pVdexDeps->pVdexDepData[i].unvfyClasses);
  }
  CHECK_LE(depsDataStart, depsDataEnd);
  return pVdexDeps;
}

void vdex_destroyDepsInfo(const vdexDeps *pVdexDeps) {
  for (u4 i = 0; i < pVdexDeps->numberOfDexFiles; ++i) {
    free((void *)pVdexDeps->pVdexDepData[i].extraStrings.strings);
    free((void *)pVdexDeps->pVdexDepData[i].assignTypeSets.pVdexDepSets);
    free((void *)pVdexDeps->pVdexDepData[i].unassignTypeSets.pVdexDepSets);
    free((void *)pVdexDeps->pVdexDepData[i].classes.pVdexDepClasses);
    free((void *)pVdexDeps->pVdexDepData[i].fields.pVdexDepFields);
    free((void *)pVdexDeps->pVdexDepData[i].directMethods.pVdexDepMethods);
    free((void *)pVdexDeps->pVdexDepData[i].virtualMethods.pVdexDepMethods);
    free((void *)pVdexDeps->pVdexDepData[i].interfaceMethods.pVdexDepMethods);
    free((void *)pVdexDeps->pVdexDepData[i].unvfyClasses.pVdexDepUnvfyClasses);
  }
  free((void *)pVdexDeps->pVdexDepData);
  free((void *)pVdexDeps);
}

void vdex_dumpDepsInfo(const u1 *vdexFileBuf, const vdexDeps *pVdexDeps) {
  LOGMSG(l_VDEBUG, "------- Vdex Deps Info -------");

  const u1 *dexFileBuf = NULL;
  u4 offset = 0;
  for (u4 i = 0; i < pVdexDeps->numberOfDexFiles; ++i) {
    const vdexDepData *pVdexDepData = &pVdexDeps->pVdexDepData[i];
    LOGMSG(l_VDEBUG, "dex file #%" PRIu32, i);
    dexFileBuf = vdex_GetNextDexFileData(vdexFileBuf, &offset);
    if (dexFileBuf == NULL) {
      LOGMSG(l_FATAL, "Failed to extract Dex file buffer from loaded Vdex");
    }

    vdexDepStrings strings = pVdexDepData->extraStrings;
    LOGMSG(l_VDEBUG, " extra strings: number_of_strings=%" PRIu32, strings.numberOfStrings);
    for (u4 i = 0; i < strings.numberOfStrings; ++i) {
      LOGMSG(l_VDEBUG, "  %04" PRIu32 ": '%s'", i, strings.strings[i]);
    }

    vdexDepTypeSet aTypes = pVdexDepData->assignTypeSets;
    LOGMSG(l_VDEBUG, " assignable type sets: number_of_sets=%" PRIu32, aTypes.numberOfEntries);
    for (u4 i = 0; i < aTypes.numberOfEntries; ++i) {
      LOGMSG(l_VDEBUG, "  %04" PRIu32 ": '%s' must be assignable to '%s'", i,
             getStringFromId(pVdexDepData, aTypes.pVdexDepSets[i].srcIndex, dexFileBuf),
             getStringFromId(pVdexDepData, aTypes.pVdexDepSets[i].dstIndex, dexFileBuf));
    }

    vdexDepTypeSet unTypes = pVdexDepData->unassignTypeSets;
    LOGMSG(l_VDEBUG, " unassignable type sets: number_of_sets=%" PRIu32, unTypes.numberOfEntries);
    for (u4 i = 0; i < unTypes.numberOfEntries; ++i) {
      LOGMSG(l_VDEBUG, "  %04" PRIu32 ": '%s' must not be assignable to '%s'", i,
             getStringFromId(pVdexDepData, unTypes.pVdexDepSets[i].srcIndex, dexFileBuf),
             getStringFromId(pVdexDepData, unTypes.pVdexDepSets[i].dstIndex, dexFileBuf));
    }

    LOGMSG(l_VDEBUG, " class dependencies: number_of_classes=%" PRIu32,
           pVdexDepData->classes.numberOfEntries);
    for (u4 i = 0; i < pVdexDepData->classes.numberOfEntries; ++i) {
      u2 accessFlags = pVdexDepData->classes.pVdexDepClasses[i].accessFlags;
      LOGMSG(l_VDEBUG, "  %04" PRIu32 ": '%s' '%s' be resolved with access flags '%" PRIu16 "'", i,
             dex_getStringByTypeIdx(dexFileBuf, pVdexDepData->classes.pVdexDepClasses[i].typeIdx),
             accessFlags == kUnresolvedMarker ? "must not" : "must", accessFlags);
    }

    LOGMSG(l_VDEBUG, " field dependencies: number_of_fields=%" PRIu32,
           pVdexDepData->fields.numberOfEntries);
    for (u4 i = 0; i < pVdexDepData->fields.numberOfEntries; ++i) {
      vdexDepFieldRes fieldRes = pVdexDepData->fields.pVdexDepFields[i];
      const dexFieldId *pDexFieldId = dex_getFieldId(dexFileBuf, fieldRes.fieldIdx);
      LOGMSG_RAW(l_VDEBUG, "   %04" PRIu32 ": '%s'->'%s':'%s' is expected to be ", i,
                 dex_getFieldDeclaringClassDescriptor(dexFileBuf, pDexFieldId),
                 dex_getFieldName(dexFileBuf, pDexFieldId),
                 dex_getFieldTypeDescriptor(dexFileBuf, pDexFieldId));
      if (fieldRes.accessFlags == kUnresolvedMarker) {
        LOGMSG_RAW(l_VDEBUG, "unresolved\n");
      } else {
        LOGMSG_RAW(l_VDEBUG, "in class '%s' and have the access flags '%" PRIu16 "'\n",
                   getStringFromId(pVdexDepData, fieldRes.declaringClassIdx, dexFileBuf),
                   fieldRes.accessFlags);
      }

      dumpDepsMethodInfo(dexFileBuf, pVdexDepData, &pVdexDepData->directMethods, "direct");
      dumpDepsMethodInfo(dexFileBuf, pVdexDepData, &pVdexDepData->virtualMethods, "virtual");
      dumpDepsMethodInfo(dexFileBuf, pVdexDepData, &pVdexDepData->interfaceMethods, "interface");

      LOGMSG(l_VDEBUG, " unverified classes: number_of_classes=%" PRIu32,
             pVdexDepData->unvfyClasses.numberOfEntries);
      for (u4 i = 0; i < pVdexDepData->unvfyClasses.numberOfEntries; ++i) {
        LOGMSG(l_VDEBUG, "  %04" PRIu32 ": '%s' is expected to be verified at runtime", i,
               dex_getStringByTypeIdx(dexFileBuf,
                                      pVdexDepData->unvfyClasses.pVdexDepUnvfyClasses[i].typeIdx));
      }
    }
  }
  LOGMSG(l_VDEBUG, "----- EOF Vdex Deps Info -----");
}

bool vdex_Unquicken(const u1 *cursor, bool enableDisassembler) {
  if (vdex_GetQuickeningInfoSize(cursor) == 0) {
    // If there is no quickening info, we bail early, as the code below expects at
    // least the size of quickening data for each method that has a code item.
    return true;
  }

  // Update Dex disassembler engine status
  dex_setDisassemblerStatus(enableDisassembler);

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

void vdex_walkDex(const u1 *cursor, bool enableDisassembler) {
  // Update Dex disassembler engine status
  dex_setDisassemblerStatus(enableDisassembler);
  if (enableDisassembler == false) {
    return;
  }

  const vdexHeader *pVdexHeader = (const vdexHeader *)cursor;
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
        dexDecompiler_walk(dexFileBuf, pDexCode, dex_getFirstInstrOff(&curDexMethod));
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
        dexDecompiler_walk(dexFileBuf, pDexCode, dex_getFirstInstrOff(&curDexMethod));
      }
    }
  }
}
