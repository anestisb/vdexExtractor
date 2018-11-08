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

#include "vdex_backend_010.h"
#include "../out_writer.h"
#include "../utils.h"
#include "vdex_common.h"
#include "vdex_decompiler_010.h"

static const u1 *quickening_info_ptr;
static const unaligned_u4 *current_code_item_ptr;
static const unaligned_u4 *current_code_item_end;

static void QuickeningInfoIt_Init(u4 dex_file_idx,
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

static bool QuickeningInfoIt_Done() { return current_code_item_ptr == current_code_item_end; }

static void QuickeningInfoIt_Advance() { current_code_item_ptr += 2; }

static u4 QuickeningInfoIt_GetCurrentCodeItemOffset() { return current_code_item_ptr[0]; }

static void GetCurrentQuickeningInfo(vdex_data_array_t *quickInfo) {
  // Add sizeof(uint32_t) to remove the length from the data pointer.
  quickInfo->data = quickening_info_ptr + current_code_item_ptr[1] + sizeof(u4);
  quickInfo->size = *(unaligned_u4 *)(quickening_info_ptr + current_code_item_ptr[1]);
}

static inline u4 decodeUint32WithOverflowCheck(const u1 **in, const u1 *end) {
  CHECK_LT(*in, end);
  return dex_readULeb128(in);
}

static void decodeDepStrings(const u1 **in, const u1 *end, vdexDepStrings_010 *depStrings) {
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

static void decodeDepTypeSet(const u1 **in, const u1 *end, vdexDepTypeSet_010 *pVdexDepTypeSet) {
  u4 numOfEntries = decodeUint32WithOverflowCheck(in, end);
  pVdexDepTypeSet->pVdexDepSets = utils_malloc(numOfEntries * sizeof(vdexDepSet_010));
  pVdexDepTypeSet->numberOfEntries = numOfEntries;
  for (u4 i = 0; i < numOfEntries; ++i) {
    pVdexDepTypeSet->pVdexDepSets[i].dstIndex = decodeUint32WithOverflowCheck(in, end);
    pVdexDepTypeSet->pVdexDepSets[i].srcIndex = decodeUint32WithOverflowCheck(in, end);
  }
}

static void decodeDepClasses(const u1 **in,
                             const u1 *end,
                             vdexDepClassResSet_010 *pVdexDepClassResSet) {
  u4 numOfEntries = decodeUint32WithOverflowCheck(in, end);
  pVdexDepClassResSet->pVdexDepClasses = utils_malloc(numOfEntries * sizeof(vdexDepClassRes_010));
  pVdexDepClassResSet->numberOfEntries = numOfEntries;
  for (u4 i = 0; i < numOfEntries; ++i) {
    pVdexDepClassResSet->pVdexDepClasses[i].typeIdx = decodeUint32WithOverflowCheck(in, end);
    pVdexDepClassResSet->pVdexDepClasses[i].accessFlags = decodeUint32WithOverflowCheck(in, end);
  }
}

static void decodeDepFields(const u1 **in,
                            const u1 *end,
                            vdexDepFieldResSet_010 *pVdexDepFieldResSet) {
  u4 numOfEntries = decodeUint32WithOverflowCheck(in, end);
  pVdexDepFieldResSet->pVdexDepFields = utils_malloc(numOfEntries * sizeof(vdexDepFieldRes_010));
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
                             vdexDepMethodResSet_010 *pVdexDepMethodResSet) {
  u4 numOfEntries = decodeUint32WithOverflowCheck(in, end);
  pVdexDepMethodResSet->pVdexDepMethods = utils_malloc(numOfEntries * sizeof(vdexDepMethodRes_010));
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
                                  vdexDepUnvfyClassesSet_010 *pVdexDepUnvfyClassesSet) {
  u4 numOfEntries = decodeUint32WithOverflowCheck(in, end);
  pVdexDepUnvfyClassesSet->pVdexDepUnvfyClasses =
      utils_malloc(numOfEntries * sizeof(vdexDepUnvfyClass_010));
  pVdexDepUnvfyClassesSet->numberOfEntries = numOfEntries;
  for (u4 i = 0; i < numOfEntries; ++i) {
    pVdexDepUnvfyClassesSet->pVdexDepUnvfyClasses[i].typeIdx =
        decodeUint32WithOverflowCheck(in, end);
  }
}

static const char *getStringFromId(const vdexDepData_010 *pVdexDepData,
                                   u4 stringId,
                                   const u1 *dexFileBuf) {
  vdexDepStrings_010 extraStrings = pVdexDepData->extraStrings;
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

static vdexDeps_010 *initDepsInfo(const u1 *vdexFileBuf) {
  vdex_data_array_t vDeps;
  vdex_010_GetVerifierDeps(vdexFileBuf, &vDeps);
  if (vDeps.size == 0) {
    // Return early, as the first thing we expect from VerifierDeps data is
    // the number of created strings, even if there is no dependency.
    return NULL;
  }

  vdexDeps_010 *pVdexDeps = utils_malloc(sizeof(vdexDeps_010));

  const vdexHeader_010 *pVdexHeader = (const vdexHeader_010 *)vdexFileBuf;
  pVdexDeps->numberOfDexFiles = pVdexHeader->numberOfDexFiles;
  pVdexDeps->pVdexDepData = utils_malloc(sizeof(vdexDepData_010) * pVdexDeps->numberOfDexFiles);

  const u1 *dexFileBuf = NULL;
  u4 offset = 0;

  const u1 *depsDataStart = vDeps.data;
  const u1 *depsDataEnd = depsDataStart + vDeps.size;

  for (u4 i = 0; i < pVdexDeps->numberOfDexFiles; ++i) {
    dexFileBuf = vdex_010_GetNextDexFileData(vdexFileBuf, &offset);
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

static bool hasDepsData(vdexDeps_010 *pVdexDeps) {
  for (u4 i = 0; i < pVdexDeps->numberOfDexFiles; ++i) {
    const vdexDepData_010 *pVdexDepData = &pVdexDeps->pVdexDepData[i];
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

static void destroyDepsInfo(const vdexDeps_010 *pVdexDeps) {
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

void vdex_backend_010_dumpDepsInfo(const u1 *vdexFileBuf) {
  // Initialize depsInfo structs
  vdexDeps_010 *pVdexDeps = initDepsInfo(vdexFileBuf);
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
    const vdexDepData_010 *pVdexDepData = &pVdexDeps->pVdexDepData[i];
    log_dis("dex file #%" PRIu32 "\n", i);
    dexFileBuf = vdex_010_GetNextDexFileData(vdexFileBuf, &offset);
    if (dexFileBuf == NULL) {
      LOGMSG(l_FATAL, "Failed to extract Dex file buffer from loaded Vdex");
    }

    vdexDepStrings_010 strings = pVdexDepData->extraStrings;
    log_dis(" extra strings: number_of_strings=%" PRIu32 "\n", strings.numberOfStrings);
    for (u4 i = 0; i < strings.numberOfStrings; ++i) {
      log_dis("  %04" PRIu32 ": '%s'\n", i, strings.strings[i]);
    }

    vdexDepTypeSet_010 aTypes = pVdexDepData->assignTypeSets;
    log_dis(" assignable type sets: number_of_sets=%" PRIu32 "\n", aTypes.numberOfEntries);
    for (u4 i = 0; i < aTypes.numberOfEntries; ++i) {
      log_dis("  %04" PRIu32 ": '%s' must be assignable to '%s'\n", i,
              getStringFromId(pVdexDepData, aTypes.pVdexDepSets[i].srcIndex, dexFileBuf),
              getStringFromId(pVdexDepData, aTypes.pVdexDepSets[i].dstIndex, dexFileBuf));
    }

    vdexDepTypeSet_010 unTypes = pVdexDepData->unassignTypeSets;
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
      vdexDepFieldRes_010 fieldRes = pVdexDepData->fields.pVdexDepFields[i];
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

int vdex_backend_010_process(const char *VdexFileName,
                             const u1 *cursor,
                             size_t bufSz,
                             const runArgs_t *pRunArgs) {
  // Basic size checks
  if (!vdex_010_SanityCheck(cursor, bufSz)) {
    LOGMSG(l_ERROR, "Malformed Vdex file");
    return -1;
  }

  const vdexHeader_010 *pVdexHeader = (const vdexHeader_010 *)cursor;
  const u1 *dexFileBuf = NULL;
  u4 offset = 0;

  // For each Dex file
  for (size_t dex_file_idx = 0; dex_file_idx < pVdexHeader->numberOfDexFiles; ++dex_file_idx) {
    vdex_data_array_t quickInfo;
    vdex_010_GetQuickeningInfo(cursor, &quickInfo);
    QuickeningInfoIt_Init(dex_file_idx, pVdexHeader->numberOfDexFiles, quickInfo.data,
                          quickInfo.size);

    dexFileBuf = vdex_010_GetNextDexFileData(cursor, &offset);
    if (dexFileBuf == NULL) {
      LOGMSG(l_ERROR, "Failed to extract 'classes%zu.dex' - skipping", dex_file_idx);
      continue;
    }

    // Check if valid Dex file
    dex_dumpHeaderInfo(dexFileBuf);
    if (!dex_isValidDex(dexFileBuf)) {
      LOGMSG(l_ERROR, "'classes%zu.dex' is an invalid Dex file - skipping", dex_file_idx);
      continue;
    }

    // For each class
    log_dis("file #%zu: classDefsSize=%" PRIu32 "\n", dex_file_idx,
            dex_getClassDefsSize(dexFileBuf));
    for (u4 i = 0; i < dex_getClassDefsSize(dexFileBuf); ++i) {
      u4 lastIdx = 0;
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
      lastIdx = 0;  // transition to next array, reset last index
      for (u4 j = 0; j < pDexClassDataHeader.directMethodsSize; ++j) {
        dexMethod curDexMethod;
        memset(&curDexMethod, 0, sizeof(dexMethod));
        dex_readClassDataMethod(&curClassDataCursor, &curDexMethod);
        dex_dumpMethodInfo(dexFileBuf, &curDexMethod, lastIdx, "direct");
        lastIdx += curDexMethod.methodIdx;

        // Skip empty methods
        if (curDexMethod.codeOff == 0) {
          continue;
        }

        if (pRunArgs->unquicken) {
          vdex_data_array_t curQuickInfo;
          curQuickInfo.data = NULL;
          curQuickInfo.size = 0;
          if (!QuickeningInfoIt_Done() &&
              curDexMethod.codeOff == QuickeningInfoIt_GetCurrentCodeItemOffset()) {
            GetCurrentQuickeningInfo(&curQuickInfo);
            QuickeningInfoIt_Advance();
          }
          if (!vdex_decompiler_010_decompile(dexFileBuf, &curDexMethod, &curQuickInfo, true)) {
            LOGMSG(l_ERROR, "Failed to decompile Dex file");
            return -1;
          }
        } else {
          vdex_decompiler_010_walk(dexFileBuf, &curDexMethod);
        }
      }

      // For each virtual method
      lastIdx = 0;  // transition to next array, reset last index
      for (u4 j = 0; j < pDexClassDataHeader.virtualMethodsSize; ++j) {
        dexMethod curDexMethod;
        memset(&curDexMethod, 0, sizeof(dexMethod));
        dex_readClassDataMethod(&curClassDataCursor, &curDexMethod);
        dex_dumpMethodInfo(dexFileBuf, &curDexMethod, lastIdx, "virtual");
        lastIdx += curDexMethod.methodIdx;

        // Skip native or abstract methods
        if (curDexMethod.codeOff == 0) {
          continue;
        }

        if (pRunArgs->unquicken) {
          vdex_data_array_t curQuickInfo;
          curQuickInfo.data = NULL;
          curQuickInfo.size = 0;
          if (!QuickeningInfoIt_Done() &&
              curDexMethod.codeOff == QuickeningInfoIt_GetCurrentCodeItemOffset()) {
            GetCurrentQuickeningInfo(&curQuickInfo);
            QuickeningInfoIt_Advance();
          }
          if (!vdex_decompiler_010_decompile(dexFileBuf, &curDexMethod, &curQuickInfo, true)) {
            LOGMSG(l_ERROR, "Failed to decompile Dex file");
            return -1;
          }
        } else {
          vdex_decompiler_010_walk(dexFileBuf, &curDexMethod);
        }
      }
    }

    if (pRunArgs->unquicken) {
      // All QuickeningInfo data should have been consumed
      if (!QuickeningInfoIt_Done()) {
        LOGMSG(l_ERROR, "Failed to use all quickening info");
        return -1;
      }
      // If unquicken was successful original checksum should verify
      u4 curChecksum = dex_computeDexCRC(dexFileBuf, dex_getFileSize(dexFileBuf));
      if (curChecksum != dex_getChecksum(dexFileBuf)) {
        // If ignore CRC errors is enabled, repair CRC (see issue #3)
        if (pRunArgs->ignoreCrc) {
          dex_repairDexCRC(dexFileBuf, dex_getFileSize(dexFileBuf));
        } else {
          LOGMSG(l_ERROR,
                 "Unexpected checksum (%" PRIx32 " vs %" PRIx32 ") - failed to unquicken Dex file",
                 curChecksum, dex_getChecksum(dexFileBuf));
          return -1;
        }
      }
    } else {
      // Repair CRC if not decompiling so we can still run Dex parsing tools against output
      dex_repairDexCRC(dexFileBuf, dex_getFileSize(dexFileBuf));
    }

    if (!outWriter_DexFile(pRunArgs, VdexFileName, dex_file_idx, dexFileBuf,
                           dex_getFileSize(dexFileBuf))) {
      return -1;
    }
  }

  return pVdexHeader->numberOfDexFiles;
}
