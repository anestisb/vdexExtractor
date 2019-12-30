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

#include "vdex_backend_021.h"

#include "../hashset/hashset.h"
#include "../out_writer.h"
#include "../utils.h"
#include "vdex_decompiler_021.h"

const u4 *pCompactOffsetTable;
u4 compactOffsetMinOffset;
const u1 *pCompactOffsetDataBegin;

static inline int POPCOUNT(uintptr_t x) {
  return (sizeof(uintptr_t) == sizeof(u4)) ? __builtin_popcount(x) : __builtin_popcountll(x);
}

static void initCompactOffset(const u1 *cursor) {
  pCompactOffsetDataBegin = cursor + (2 * sizeof(u4));
  compactOffsetMinOffset = ((u4 *)cursor)[0];  // First 4 bytes are are the minimum offset
  u4 tableOffset = ((u4 *)cursor)[1];          // Next 4 bytes are the table offset
  pCompactOffsetTable = (u4 *)(pCompactOffsetDataBegin + tableOffset);
}

// This value is coupled with the leb chunk bitmask. That logic must also be adjusted when the
// integer is modified.
static const size_t kElementsPerIndex = 16;

// Leb block format:
// [uint16_t] 16 bit mask for what indexes actually have a non zero offset for the chunk.
// [lebs] Up to 16 lebs encoded using leb128, one leb bit. The leb specifies how the offset
// changes compared to the previous index.
static u4 getOffset(u4 index) {
  const u4 offset = pCompactOffsetTable[index / kElementsPerIndex];
  const size_t bit_index = index % kElementsPerIndex;

  const u1 *block = pCompactOffsetDataBegin + offset;
  u2 bit_mask = *block;
  ++block;
  bit_mask = (bit_mask << kBitsPerByte) | *block;
  ++block;
  if ((bit_mask & (1 << bit_index)) == 0) {
    // Bit is not set means the offset is 0.
    return 0u;
  }
  // Trim off the bits above the index we want and count how many bits are set. This is how many
  // lebs we need to decode.
  size_t count = POPCOUNT((uintptr_t)(bit_mask) << (kBitsPerIntPtrT - 1 - bit_index));
  CHECK_GT(count, 0u);
  u4 current_offset = compactOffsetMinOffset;
  do {
    current_offset += dex_readULeb128(&block);
    --count;
  } while (count > 0);
  return current_offset;
}

static size_t quickenInfoTableSizeInBytes(const u1 *data, u4 dataSize) {
  const u1 *tableData = data;
  u4 elementsNum = dataSize != 0 ? dex_readULeb128(&tableData) : 0u;
  return tableData + elementsNum * 2 - data;
}

static void getQuickeningInfoAt(const vdex_data_array_t *pQuickInfo,
                                u4 offset,
                                vdex_data_array_t *pSubQuickInfo) {
  // Subtract offset of one since 0 represents unused and cannot be in the table.
  CHECK_LE(offset, pQuickInfo->size);
  const u1 *remaining = pQuickInfo->data + (offset - 1);
  const u4 remainingSize = pQuickInfo->size - (offset - 1);

  pSubQuickInfo->data = remaining;
  pSubQuickInfo->size = quickenInfoTableSizeInBytes(remaining, remainingSize);
  pSubQuickInfo->offset = pQuickInfo->offset + (remaining - pQuickInfo->data);
}

static inline u4 decodeUint32WithOverflowCheck(const u1 **in, const u1 *end) {
  CHECK_LT(*in, end);
  return dex_readULeb128(in);
}

static void decodeDepStrings(const u1 **in, const u1 *end, vdexDepStrings_021 *depStrings) {
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

static void decodeDepTypeSet(const u1 **in, const u1 *end, vdexDepTypeSet_021 *pVdexDepTypeSet) {
  u4 numOfEntries = decodeUint32WithOverflowCheck(in, end);
  pVdexDepTypeSet->pVdexDepSets = utils_malloc(numOfEntries * sizeof(vdexDepSet_021));
  pVdexDepTypeSet->numberOfEntries = numOfEntries;
  for (u4 i = 0; i < numOfEntries; ++i) {
    pVdexDepTypeSet->pVdexDepSets[i].dstIndex = decodeUint32WithOverflowCheck(in, end);
    pVdexDepTypeSet->pVdexDepSets[i].srcIndex = decodeUint32WithOverflowCheck(in, end);
  }
}

static void decodeDepClasses(const u1 **in,
                             const u1 *end,
                             vdexDepClassResSet_021 *pVdexDepClassResSet) {
  u4 numOfEntries = decodeUint32WithOverflowCheck(in, end);
  pVdexDepClassResSet->pVdexDepClasses = utils_malloc(numOfEntries * sizeof(vdexDepClassRes_021));
  pVdexDepClassResSet->numberOfEntries = numOfEntries;
  for (u4 i = 0; i < numOfEntries; ++i) {
    pVdexDepClassResSet->pVdexDepClasses[i].typeIdx = decodeUint32WithOverflowCheck(in, end);
    pVdexDepClassResSet->pVdexDepClasses[i].accessFlags = decodeUint32WithOverflowCheck(in, end);
  }
}

static void decodeDepFields(const u1 **in,
                            const u1 *end,
                            vdexDepFieldResSet_021 *pVdexDepFieldResSet) {
  u4 numOfEntries = decodeUint32WithOverflowCheck(in, end);
  pVdexDepFieldResSet->pVdexDepFields = utils_malloc(numOfEntries * sizeof(vdexDepFieldRes_021));
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
                             vdexDepMethodResSet_021 *pVdexDepMethodResSet) {
  u4 numOfEntries = decodeUint32WithOverflowCheck(in, end);
  pVdexDepMethodResSet->pVdexDepMethods = utils_malloc(numOfEntries * sizeof(vdexDepMethodRes_021));
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
                                  vdexDepUnvfyClassesSet_021 *pVdexDepUnvfyClassesSet) {
  u4 numOfEntries = decodeUint32WithOverflowCheck(in, end);
  pVdexDepUnvfyClassesSet->pVdexDepUnvfyClasses =
      utils_malloc(numOfEntries * sizeof(vdexDepUnvfyClass_021));
  pVdexDepUnvfyClassesSet->numberOfEntries = numOfEntries;
  for (u4 i = 0; i < numOfEntries; ++i) {
    pVdexDepUnvfyClassesSet->pVdexDepUnvfyClasses[i].typeIdx =
        decodeUint32WithOverflowCheck(in, end);
  }
}

static const char *getStringFromId(const vdexDepData_021 *pVdexDepData,
                                   u4 stringId,
                                   const u1 *dexFileBuf) {
  vdexDepStrings_021 extraStrings = pVdexDepData->extraStrings;
  u4 numIdsInDex = dex_getStringIdsSize(dexFileBuf);
  if (stringId < numIdsInDex) {
    return dex_getStringDataByIdx(dexFileBuf, stringId);
  } else {
    // Adjust offset
    stringId -= numIdsInDex;
    CHECK_LT(stringId, extraStrings.numberOfStrings);
    return extraStrings.strings[stringId];
  }
}

static vdexDeps_021 *initDepsInfo(const u1 *vdexFileBuf) {
  vdex_data_array_t vDeps;
  vdex_021_GetVerifierDeps(vdexFileBuf, &vDeps);

  if (vDeps.size == 0) {
    // Return early, as the first thing we expect from VerifierDeps data is
    // the number of created strings, even if there is no dependency.
    return NULL;
  }

  vdexDeps_021 *pVdexDeps = utils_malloc(sizeof(vdexDeps_021));

  const vdexHeader_021 *pVdexHeader = (const vdexHeader_021 *)vdexFileBuf;
  pVdexDeps->numberOfDexFiles = pVdexHeader->numberOfDexFiles;
  pVdexDeps->pVdexDepData = utils_malloc(sizeof(vdexDepData_021) * pVdexDeps->numberOfDexFiles);

  const u1 *dexFileBuf = NULL;
  u4 offset = 0;

  const u1 *depsDataStart = vDeps.data;
  const u1 *depsDataEnd = depsDataStart + vDeps.size;

  for (u4 i = 0; i < pVdexDeps->numberOfDexFiles; ++i) {
    dexFileBuf = vdex_021_GetNextDexFileData(vdexFileBuf, &offset);
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

    // Process encoded methods
    decodeDepMethods(&depsDataStart, depsDataEnd, &pVdexDeps->pVdexDepData[i].methods);

    // Process encoded unverified classes
    decodeDepUnvfyClasses(&depsDataStart, depsDataEnd, &pVdexDeps->pVdexDepData[i].unvfyClasses);
  }
  CHECK_LE(depsDataStart, depsDataEnd);
  return pVdexDeps;
}

static bool hasDepsData(vdexDeps_021 *pVdexDeps) {
  for (u4 i = 0; i < pVdexDeps->numberOfDexFiles; ++i) {
    const vdexDepData_021 *pVdexDepData = &pVdexDeps->pVdexDepData[i];
    if (pVdexDepData->extraStrings.numberOfStrings > 0 ||
        pVdexDepData->assignTypeSets.numberOfEntries > 0 ||
        pVdexDepData->unassignTypeSets.numberOfEntries > 0 ||
        pVdexDepData->classes.numberOfEntries > 0 || pVdexDepData->fields.numberOfEntries > 0 ||
        pVdexDepData->methods.numberOfEntries > 0 ||
        pVdexDepData->unvfyClasses.numberOfEntries > 0) {
      return true;
    }
  }

  return false;
}

static void destroyDepsInfo(const vdexDeps_021 *pVdexDeps) {
  for (u4 i = 0; i < pVdexDeps->numberOfDexFiles; ++i) {
    free((void *)pVdexDeps->pVdexDepData[i].extraStrings.strings);
    free((void *)pVdexDeps->pVdexDepData[i].assignTypeSets.pVdexDepSets);
    free((void *)pVdexDeps->pVdexDepData[i].unassignTypeSets.pVdexDepSets);
    free((void *)pVdexDeps->pVdexDepData[i].classes.pVdexDepClasses);
    free((void *)pVdexDeps->pVdexDepData[i].fields.pVdexDepFields);
    free((void *)pVdexDeps->pVdexDepData[i].methods.pVdexDepMethods);
    free((void *)pVdexDeps->pVdexDepData[i].unvfyClasses.pVdexDepUnvfyClasses);
  }
  free((void *)pVdexDeps->pVdexDepData);
  free((void *)pVdexDeps);
}

void vdex_backend_021_dumpDepsInfo(const u1 *vdexFileBuf) {
  // Not all Vdex files have Dex data to process
  if (!vdex_021_hasDexSection(vdexFileBuf)) {
    LOGMSG(l_DEBUG, "Vdex has no Dex data - skipping");
    return;
  }

  // Initialize depsInfo structs
  vdexDeps_021 *pVdexDeps = initDepsInfo(vdexFileBuf);
  if (pVdexDeps == NULL) {
    LOGMSG(l_WARN, "Malformed verified dependencies data");
    return;
  }

  if (!hasDepsData(pVdexDeps)) {
    LOGMSG(l_DEBUG, "Empty verified dependencies data");
    goto cleanup;
  }

  log_dis("------- Vdex Deps Info -------\n");

  const u1 *dexFileBuf = NULL;
  u4 offset = 0;
  for (u4 i = 0; i < pVdexDeps->numberOfDexFiles; ++i) {
    const vdexDepData_021 *pVdexDepData = &pVdexDeps->pVdexDepData[i];
    log_dis("dex file #%" PRIu32 "\n", i);
    dexFileBuf = vdex_021_GetNextDexFileData(vdexFileBuf, &offset);
    if (dexFileBuf == NULL) {
      LOGMSG(l_ERROR, "Failed to extract Dex file buffer from loaded Vdex");
      return;
    }

    vdexDepStrings_021 strings = pVdexDepData->extraStrings;
    log_dis(" extra strings: number_of_strings=%" PRIu32 "\n", strings.numberOfStrings);
    for (u4 i = 0; i < strings.numberOfStrings; ++i) {
      log_dis("  %04" PRIu32 ": '%s'\n", i, strings.strings[i]);
    }

    vdexDepTypeSet_021 aTypes = pVdexDepData->assignTypeSets;
    log_dis(" assignable type sets: number_of_sets=%" PRIu32 "\n", aTypes.numberOfEntries);
    for (u4 i = 0; i < aTypes.numberOfEntries; ++i) {
      log_dis("  %04" PRIu32 ": '%s' must be assignable to '%s'\n", i,
              getStringFromId(pVdexDepData, aTypes.pVdexDepSets[i].srcIndex, dexFileBuf),
              getStringFromId(pVdexDepData, aTypes.pVdexDepSets[i].dstIndex, dexFileBuf));
    }

    vdexDepTypeSet_021 unTypes = pVdexDepData->unassignTypeSets;
    log_dis(" unassignable type sets: number_of_sets=%" PRIu32 "\n", unTypes.numberOfEntries);
    for (u4 i = 0; i < unTypes.numberOfEntries; ++i) {
      log_dis("  %04" PRIu32 ": '%s' must not be assignable to '%s'\n", i,
              getStringFromId(pVdexDepData, unTypes.pVdexDepSets[i].srcIndex, dexFileBuf),
              getStringFromId(pVdexDepData, unTypes.pVdexDepSets[i].dstIndex, dexFileBuf));
    }

    log_dis(" class dependencies: number_of_classes=%" PRIu32 "\n",
            pVdexDepData->classes.numberOfEntries);
    for (u4 i = 0; i < pVdexDepData->classes.numberOfEntries; ++i) {
      u2 accessFlags = pVdexDepData->classes.pVdexDepClasses[i].accessFlags;
      log_dis("  %04" PRIu32 ": '%s' '%s' be resolved with access flags '%" PRIu16 "'\n", i,
              dex_getStringByTypeIdx(dexFileBuf, pVdexDepData->classes.pVdexDepClasses[i].typeIdx),
              accessFlags == kUnresolvedMarker ? "must not" : "must", accessFlags);
    }

    log_dis(" field dependencies: number_of_fields=%" PRIu32 "\n",
            pVdexDepData->fields.numberOfEntries);
    for (u4 i = 0; i < pVdexDepData->fields.numberOfEntries; ++i) {
      vdexDepFieldRes_021 fieldRes = pVdexDepData->fields.pVdexDepFields[i];
      const dexFieldId *pDexFieldId = dex_getFieldId(dexFileBuf, fieldRes.fieldIdx);
      log_dis("  %04" PRIu32 ": '%s'->'%s':'%s' is expected to be ", i,
              dex_getFieldDeclaringClassDescriptor(dexFileBuf, pDexFieldId),
              dex_getFieldName(dexFileBuf, pDexFieldId),
              dex_getFieldTypeDescriptor(dexFileBuf, pDexFieldId));
      if (fieldRes.accessFlags == kUnresolvedMarker) {
        log_dis("unresolved\n");
      } else {
        log_dis("in class '%s' and have the access flags '%" PRIu16 "'\n",
                getStringFromId(pVdexDepData, fieldRes.declaringClassIdx, dexFileBuf),
                fieldRes.accessFlags);
      }
    }

    log_dis(" method dependencies: number_of_methods=%" PRIu32 "\n",
            pVdexDepData->methods.numberOfEntries);
    for (u4 i = 0; i < pVdexDepData->methods.numberOfEntries; ++i) {
      const dexMethodId *pDexMethodId =
          dex_getMethodId(dexFileBuf, pVdexDepData->methods.pVdexDepMethods[i].methodIdx);
      u2 accessFlags = pVdexDepData->methods.pVdexDepMethods[i].accessFlags;
      const char *methodSig = dex_getMethodSignature(dexFileBuf, pDexMethodId);
      log_dis("  %04" PRIu32 ": '%s'->'%s':'%s' is expected to be ", i,
              dex_getMethodDeclaringClassDescriptor(dexFileBuf, pDexMethodId),
              dex_getMethodName(dexFileBuf, pDexMethodId), methodSig);
      free((void *)methodSig);
      if (accessFlags == kUnresolvedMarker) {
        log_dis("unresolved\n");
      } else {
        log_dis(
            "in class '%s', have the access flags '%" PRIu16 "'\n",
            getStringFromId(pVdexDepData,
                            pVdexDepData->methods.pVdexDepMethods[i].declaringClassIdx, dexFileBuf),
            accessFlags);
      }
    }

    log_dis(" unverified classes: number_of_classes=%" PRIu32 "\n",
            pVdexDepData->unvfyClasses.numberOfEntries);
    for (u4 i = 0; i < pVdexDepData->unvfyClasses.numberOfEntries; ++i) {
      log_dis("  %04" PRIu32 ": '%s' is expected to be verified at runtime\n", i,
              dex_getStringByTypeIdx(dexFileBuf,
                                     pVdexDepData->unvfyClasses.pVdexDepUnvfyClasses[i].typeIdx));
    }
  }
  log_dis("----- EOF Vdex Deps Info -----\n");

// Cleanup
cleanup:
  destroyDepsInfo(pVdexDeps);
}

int vdex_backend_021_process(const char *VdexFileName,
                             const u1 *cursor,
                             size_t bufSz,
                             const runArgs_t *pRunArgs) {
  int ret = 0;

  // Basic size checks
  if (!vdex_021_SanityCheck(cursor, bufSz)) {
    LOGMSG(l_ERROR, "Malformed Vdex file");
    return -1;
  }

  // Not all Vdex files have Dex data to process
  if (!vdex_021_hasDexSection(cursor)) {
    LOGMSG(l_DEBUG, "Vdex has no Dex data - skipping");
    return 0;
  }

  const vdexHeader_021 *pVdexHeader = (const vdexHeader_021 *)cursor;
  const u1 *dexFileBuf = NULL;
  u4 offset = 0;

  // For each Dex file
  for (size_t dex_file_idx = 0; dex_file_idx < pVdexHeader->numberOfDexFiles; ++dex_file_idx) {
    dexFileBuf = vdex_021_GetNextDexFileData(cursor, &offset);
    if (dexFileBuf == NULL) {
      LOGMSG(l_ERROR, "Failed to extract 'classes%zu.dex' - skipping", dex_file_idx);
      continue;
    }

    // Check if valid Dex or CompactDex file
    dex_dumpHeaderInfo(dexFileBuf);
    if (!dex_isValidDex(dexFileBuf) && !dex_isValidCDex(dexFileBuf)) {
      LOGMSG(l_ERROR, "'classes%zu.dex' is an invalid Dex file - skipping", dex_file_idx);
      continue;
    }

    vdex_data_array_t quickenInfo, quickenInfoOffTable;
    vdex_021_GetQuickeningInfo(cursor, &quickenInfo);

    // Check if there is something to decompile
    if (quickenInfo.size == 0) {
      LOGMSG(l_DEBUG, "Nothing to decompile in 'classes%zu.dex'", dex_file_idx);
    } else {
      vdex_021_GetQuickenInfoOffsetTable(dexFileBuf, &quickenInfo, &quickenInfoOffTable);
      initCompactOffset(quickenInfoOffTable.data);
    }

    // Make sure to not unquicken the same code item multiple times.
    hashset_t unquickened_code_items = hashset_create();
    if (!unquickened_code_items) {
      LOGMSG(l_ERROR, "Failed to create hashset");
      return -1;
    }

    // For each class
    log_dis("file #%zu: classDefsSize=%" PRIu32 "\n", dex_file_idx,
            dex_getClassDefsSize(dexFileBuf));
    for (u4 i = 0; i < dex_getClassDefsSize(dexFileBuf); ++i) {
      const dexClassDef *pDexClassDef = dex_getClassDef(dexFileBuf, i);

      dex_dumpClassInfo(dexFileBuf, i);

      // Last read field or method index to apply delta to
      u4 lastIdx = 0;

      // Cursor for currently processed class data item
      const u1 *curClassDataCursor;
      if (pDexClassDef->classDataOff == 0) {
        continue;
      } else {
        curClassDataCursor = dex_getDataAddr(dexFileBuf) + pDexClassDef->classDataOff;
      }

      dexClassDataHeader pDexClassDataHeader;
      memset(&pDexClassDataHeader, 0, sizeof(dexClassDataHeader));
      dex_readClassDataHeader(&curClassDataCursor, &pDexClassDataHeader);

      // Skip static fields
      for (u4 j = 0; j < pDexClassDataHeader.staticFieldsSize; ++j) {
        dexField pDexField;
        memset(&pDexField, 0, sizeof(dexField));
        dex_readClassDataField(&curClassDataCursor, &pDexField);

        // APIs are unhidden regardless if we're decompiling or not
        dex_unhideAccessFlags((u1 *)curClassDataCursor,
                              dex_decodeAccessFlagsFromDex(pDexField.accessFlags), false);
      }

      // Skip instance fields
      for (u4 j = 0; j < pDexClassDataHeader.instanceFieldsSize; ++j) {
        dexField pDexField;
        memset(&pDexField, 0, sizeof(dexField));
        dex_readClassDataField(&curClassDataCursor, &pDexField);

        // APIs are unhidden regardless if we're decompiling or not
        dex_unhideAccessFlags((u1 *)curClassDataCursor,
                              dex_decodeAccessFlagsFromDex(pDexField.accessFlags), false);
      }

      // For each direct method
      lastIdx = 0;
      for (u4 j = 0; j < pDexClassDataHeader.directMethodsSize; ++j) {
        dexMethod curDexMethod;
        memset(&curDexMethod, 0, sizeof(dexMethod));
        dex_readClassDataMethod(&curClassDataCursor, &curDexMethod);
        dex_dumpMethodInfo(dexFileBuf, &curDexMethod, lastIdx, "direct");

        // APIs are unhidden regardless if we're decompiling or not
        dex_unhideAccessFlags((u1 *)curClassDataCursor,
                              dex_decodeAccessFlagsFromDex(curDexMethod.accessFlags), true);

        // Skip empty methods
        if (curDexMethod.codeOff == 0) {
          goto next_dmethod;
        }

        if (pRunArgs->unquicken) {
          // Check if we've already unquickened the code item
          u2 *pCode = NULL;
          u4 codeSize = 0;
          dex_getCodeItemInfo(dexFileBuf, &curDexMethod, &pCode, &codeSize);
          if (hashset_is_member(unquickened_code_items, (void *)pCode)) {
            vdex_decompiler_021_walk(dexFileBuf, &curDexMethod);
            goto next_dmethod;
          }

          // Since new code item, add to set
          hashset_add(unquickened_code_items, (void *)pCode);

          // Offset being 0 means not quickened.
          const u4 qOffset = getOffset(lastIdx + curDexMethod.methodIdx);

          // Get quickenData for method and decompile
          vdex_data_array_t quickenData;
          memset(&quickenData, 0, sizeof(vdex_data_array_t));
          if (quickenInfo.size != 0 && qOffset != 0u) {
            getQuickeningInfoAt(&quickenInfo, qOffset, &quickenData);
          }

          if (!vdex_decompiler_021_decompile(dexFileBuf, &curDexMethod, &quickenData, true)) {
            LOGMSG(l_ERROR, "Failed to decompile Dex file");
            hashset_destroy(unquickened_code_items);
            return -1;
          }

        next_dmethod:
          // Update lastIdx since followings delta_idx are based on 1st elements idx
          lastIdx += curDexMethod.methodIdx;
        } else {
          vdex_decompiler_021_walk(dexFileBuf, &curDexMethod);
        }
      }  // EOF direct methods iterator

      // For each virtual method
      lastIdx = 0;
      for (u4 j = 0; j < pDexClassDataHeader.virtualMethodsSize; ++j) {
        dexMethod curDexMethod;
        memset(&curDexMethod, 0, sizeof(dexMethod));
        dex_readClassDataMethod(&curClassDataCursor, &curDexMethod);
        dex_dumpMethodInfo(dexFileBuf, &curDexMethod, lastIdx, "virtual");

        // APIs are unhidden regardless if we're decompiling or not
        dex_unhideAccessFlags((u1 *)curClassDataCursor,
                              dex_decodeAccessFlagsFromDex(curDexMethod.accessFlags), true);

        // Skip native or abstract methods
        if (curDexMethod.codeOff == 0) {
          goto next_vmethod;
        }

        if (pRunArgs->unquicken) {
          // Check if we've already unquickened the code item
          u2 *pCode = NULL;
          u4 codeSize = 0;
          dex_getCodeItemInfo(dexFileBuf, &curDexMethod, &pCode, &codeSize);
          if (hashset_is_member(unquickened_code_items, (void *)pCode)) {
            vdex_decompiler_021_walk(dexFileBuf, &curDexMethod);
            goto next_vmethod;
          }

          // Since new code item, add to set
          hashset_add(unquickened_code_items, (void *)pCode);

          // Offset being 0 means not quickened.
          const u4 qOffset = getOffset(lastIdx + curDexMethod.methodIdx);

          // Get quickenData for method and decompile
          vdex_data_array_t quickenData;
          memset(&quickenData, 0, sizeof(vdex_data_array_t));
          if (quickenInfo.size != 0 && qOffset != 0u) {
            getQuickeningInfoAt(&quickenInfo, qOffset, &quickenData);
          }

          if (!vdex_decompiler_021_decompile(dexFileBuf, &curDexMethod, &quickenData, true)) {
            LOGMSG(l_ERROR, "Failed to decompile Dex file");
            hashset_destroy(unquickened_code_items);
            return -1;
          }

        next_vmethod:
          // Update lastIdx since followings delta_idx are based on 1st elements idx
          lastIdx += curDexMethod.methodIdx;
        } else {
          vdex_decompiler_021_walk(dexFileBuf, &curDexMethod);
        }
      }  // EOF virtual methods iterator
    }

    // Destroy hashset for current dex file
    hashset_destroy(unquickened_code_items);

    // Some adjustments that are needed for the deduplicated shared data section
    const u1 *dataBuf = NULL;
    u4 dataSize = 0;
    if (dex_checkType(dexFileBuf) == kCompactDex) {
      cdexHeader *pCdexHeader = (cdexHeader *)dexFileBuf;
      u4 mainSectionSize = pCdexHeader->fileSize;
      u4 shared_section_size = pCdexHeader->dataSize;
      const u1 *origDataAddr = dex_getDataAddr(dexFileBuf);

      // The shared section will be serialized right after the dex file.
      pCdexHeader->dataOff = pCdexHeader->fileSize;
      pCdexHeader->fileSize += shared_section_size;

      // Allocate a new map
      const u1 *cdexBuf = utils_malloc(pCdexHeader->fileSize);

      // Copy main section
      memcpy((void *)cdexBuf, dexFileBuf, mainSectionSize);

      // Copy data section
      memcpy((void *)(cdexBuf + mainSectionSize), origDataAddr, shared_section_size);

      dataBuf = cdexBuf;
      dataSize = pCdexHeader->fileSize;
    } else {
      dataBuf = dexFileBuf;
      dataSize = dex_getFileSize(dexFileBuf);
    }

    if (pRunArgs->unquicken) {
      // TODO: Update this after a method to convert CDEX->DEX is decided
      if (dex_checkType(dataBuf) == kCompactDex) {
        dex_repairDexCRC(dataBuf, dataSize);
      } else {
        // If unquicken was successful original checksum should verify
        u4 curChecksum = dex_computeDexCRC(dataBuf, dataSize);
        if (curChecksum != dex_getChecksum(dataBuf)) {
          // If ignore CRC errors is enabled, repair CRC (see issue #3)
          if (pRunArgs->ignoreCrc) {
            dex_repairDexCRC(dataBuf, dataSize);
          } else {
            LOGMSG(l_ERROR,
                   "Unexpected checksum (%" PRIx32 " vs %" PRIx32
                   ") - failed to unquicken Dex file",
                   curChecksum, dex_getChecksum(dataBuf));
            ret = -1;
            goto loop_end;
          }
        }
      }
    } else {
      // Repair CRC if not decompiling so we can still run Dex parsing tools against output
      dex_repairDexCRC(dataBuf, dataSize);
    }

    if (!outWriter_DexFile(pRunArgs, VdexFileName, dex_file_idx, dataBuf, dataSize)) {
      ret = -1;
      goto loop_end;
    }

  loop_end:
    if (dex_checkType(dataBuf) == kCompactDex) {
      free((void *)dataBuf);
    }

    // Check if we have a cached error from current dexFile
    if (ret != 0) {
      return ret;
    }
  }  // EOF of dex file iterator

  return pVdexHeader->numberOfDexFiles;
}
