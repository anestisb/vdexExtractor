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

#include "dex.h"
#include "utils.h"

static inline u2 get2LE(unsigned char const *pSrc) { return pSrc[0] | (pSrc[1] << 8); }

// Helper for dumpInstruction(), which builds the string
// representation for the index in the given instruction.
// Returns a pointer to a buffer of sufficient size.
static void indexString(const u1 *dexFileBuf, u2 *codePtr, char *buf, size_t bufSize) {
  // TODO: Indexing is failing for most signature types, needs more debugging
  return;

  const dexHeader *pDexHeader = (const dexHeader *)dexFileBuf;

  static const u4 kInvalidIndex = USHRT_MAX;
  // Determine index and width of the string.
  u4 index = 0;
  u4 secondary_index = kInvalidIndex;
  u4 width = 4;
  switch (kInstructionFormats[dexInstr_getOpcode(codePtr)]) {
    // SOME NOT SUPPORTED:
    // case k20bc:
    case k21c:
    case k35c:
    // case k35ms:
    case k3rc:
      // case k3rms:
      // case k35mi:
      // case k3rmi:
      index = dexInstr_getVRegB(codePtr);
      width = 4;
      break;
    case k31c:
      index = dexInstr_getVRegB(codePtr);
      width = 8;
      break;
    case k22c:
      // case k22cs:
      index = dexInstr_getVRegC(codePtr);
      width = 4;
      break;
    case k45cc:
    case k4rcc:
      index = dexInstr_getVRegB(codePtr);
      secondary_index = dexInstr_getVRegH(codePtr);
      width = 4;
      break;
    default:
      break;
  }  // switch

  // Determine index type.
  size_t outSize = 0;
  switch (kInstructionIndexTypes[dexInstr_getOpcode(codePtr)]) {
    case kIndexUnknown:
      // This function should never get called for this type, but do
      // something sensible here, just to help with debugging.
      outSize = snprintf(buf, bufSize, "<unknown-index>");
      break;
    case kIndexNone:
      // This function should never get called for this type, but do
      // something sensible here, just to help with debugging.
      outSize = snprintf(buf, bufSize, "<no-index>");
      break;
    case kIndexTypeRef:
      if (index < pDexHeader->typeIdsSize) {
        const char *tp = dex_getStringByTypeIdx(dexFileBuf, index);
        outSize = snprintf(buf, bufSize, "%s // type@%0*x", tp, width, index);
      } else {
        outSize = snprintf(buf, bufSize, "<type?> // type@%0*x", width, index);
      }
      break;
    case kIndexStringRef:
      if (index < pDexHeader->stringIdsSize) {
        const char *st = dex_getStringDataByIdx(dexFileBuf, index);
        outSize = snprintf(buf, bufSize, "\"%s\" // string@%0*x", st, width, index);
      } else {
        outSize = snprintf(buf, bufSize, "<string?> // string@%0*x", width, index);
      }
      break;
    case kIndexMethodRef:
      if (index < pDexHeader->methodIdsSize) {
        const dexMethodId *pDexMethodId = dex_getMethodId(dexFileBuf, index);
        const char *name = dex_getStringDataByIdx(dexFileBuf, pDexMethodId->nameIdx);
        const char *signature = dex_getMethodSignature(dexFileBuf, pDexMethodId);
        const char *backDescriptor = dex_getStringByTypeIdx(dexFileBuf, pDexMethodId->classIdx);
        outSize = snprintf(buf, bufSize, "%s.%s:%s // method@%0*x", backDescriptor, name, signature,
                           width, index);
      } else {
        outSize = snprintf(buf, bufSize, "<method?> // method@%0*x", width, index);
      }
      break;
    case kIndexFieldRef:
      if (index < pDexHeader->fieldIdsSize) {
        const dexFieldId *pDexFieldId = dex_getFieldId(dexFileBuf, index);
        const char *name = dex_getStringDataByIdx(dexFileBuf, pDexFieldId->nameIdx);
        const char *typeDescriptor = dex_getStringByTypeIdx(dexFileBuf, pDexFieldId->typeIdx);
        const char *backDescriptor = dex_getStringByTypeIdx(dexFileBuf, pDexFieldId->classIdx);
        outSize = snprintf(buf, bufSize, "%s.%s:%s // field@%0*x", backDescriptor, name,
                           typeDescriptor, width, index);
      } else {
        outSize = snprintf(buf, bufSize, "<field?> // field@%0*x", width, index);
      }
      break;
    case kIndexVtableOffset:
      outSize = snprintf(buf, bufSize, "[%0*x] // vtable #%0*x", width, index, width, index);
      break;
    case kIndexFieldOffset:
      outSize = snprintf(buf, bufSize, "[obj+%0*x]", width, index);
      break;
    case kIndexMethodAndProtoRef: {
      const char *methodStr = "<method?>";
      const char *protoStr = "<proto?>";
      if (index < pDexHeader->methodIdsSize) {
        const dexMethodId *pDexMethodId = dex_getMethodId(dexFileBuf, index);
        const char *name = dex_getStringDataByIdx(dexFileBuf, pDexMethodId->nameIdx);
        const char *signature = dex_getMethodSignature(dexFileBuf, pDexMethodId);
        const char *backDescriptor = dex_getStringByTypeIdx(dexFileBuf, pDexMethodId->classIdx);

        size_t actualMethodStrSz = strlen(backDescriptor) + strlen(name) + strlen(signature) + 3;
        char *actualMethodStr = util_calloc(actualMethodStrSz);
        snprintf(actualMethodStr, actualMethodStrSz, "%s.%s:%s", backDescriptor, name, signature);
        methodStr = actualMethodStr;
      }
      if (secondary_index < pDexHeader->protoIdsSize) {
        const dexProtoId *pDexProtoId = dex_getProtoId(dexFileBuf, secondary_index);
        protoStr = dex_getProtoSignature(dexFileBuf, pDexProtoId);
      }
      outSize = snprintf(buf, bufSize, "%s, %s // method@%0*x, proto@%0*x", methodStr, protoStr,
                         width, index, width, secondary_index);
      break;
    }
    case kIndexCallSiteRef:
      // Call site information is too large to detail in disassembly so just output the index.
      outSize = snprintf(buf, bufSize, "call_site@%0*x", width, index);
      break;
    // SOME NOT SUPPORTED:
    // case kIndexVaries:
    // case kIndexInlineMethod:
    default:
      outSize = snprintf(buf, bufSize, "<?>");
      break;
  }  // switch

  // Determine success of string construction.
  if (outSize >= bufSize) {
    // The buffer wasn't big enough
    LOGMSG(l_FATAL, "Dex dump instruction indexString buffer wasn't big enough (%zu vs %zu)",
           bufSize, outSize);
  }
}

bool dex_isValidDexMagic(const dexHeader *pDexHeader) {
  // Validate magic number
  if (memcmp(pDexHeader->magic.dex, kDexMagic, sizeof(kDexMagic)) != 0) {
    return false;
  }

  // Validate magic version
  const char *version = pDexHeader->magic.ver;
  for (u4 i = 0; i < kNumDexVersions; i++) {
    if (memcmp(version, kDexMagicVersions[i], kDexVersionLen) == 0) {
      LOGMSG(l_DEBUG, "Dex version '%s' detected", pDexHeader->magic.ver);
      return true;
    }
  }
  return false;
}

void dex_dumpHeaderInfo(const dexHeader *pDexHeader) {
  char *sigHex = util_bin2hex(pDexHeader->signature, kSHA1Len);

  LOGMSG(l_VDEBUG, "------ Dex Header Info ------");
  LOGMSG(l_VDEBUG, "magic        : %.3s-%.3s", pDexHeader->magic.dex, pDexHeader->magic.ver);
  LOGMSG(l_VDEBUG, "checksum     : %" PRIx32 " (%" PRIu32 ")", pDexHeader->checksum,
         pDexHeader->checksum);
  LOGMSG(l_VDEBUG, "signature    : %s", sigHex);
  LOGMSG(l_VDEBUG, "fileSize     : %" PRIx32 " (%" PRIu32 ")", pDexHeader->fileSize,
         pDexHeader->fileSize);
  LOGMSG(l_VDEBUG, "headerSize   : %" PRIx32 " (%" PRIu32 ")", pDexHeader->headerSize,
         pDexHeader->headerSize);
  LOGMSG(l_VDEBUG, "endianTag    : %" PRIx32 " (%" PRIu32 ")", pDexHeader->endianTag,
         pDexHeader->endianTag);
  LOGMSG(l_VDEBUG, "linkSize     : %" PRIx32 " (%" PRIu32 ")", pDexHeader->linkSize,
         pDexHeader->linkSize);
  LOGMSG(l_VDEBUG, "linkOff      : %" PRIx32 " (%" PRIu32 ")", pDexHeader->linkOff,
         pDexHeader->linkOff);
  LOGMSG(l_VDEBUG, "mapOff       : %" PRIx32 " (%" PRIu32 ")", pDexHeader->mapOff,
         pDexHeader->mapOff);
  LOGMSG(l_VDEBUG, "stringIdsSize: %" PRIx32 " (%" PRIu32 ")", pDexHeader->stringIdsSize,
         pDexHeader->stringIdsSize);
  LOGMSG(l_VDEBUG, "stringIdsOff : %" PRIx32 " (%" PRIu32 ")", pDexHeader->stringIdsOff,
         pDexHeader->stringIdsOff);
  LOGMSG(l_VDEBUG, "typeIdsSize  : %" PRIx32 " (%" PRIu32 ")", pDexHeader->typeIdsSize,
         pDexHeader->typeIdsSize);
  LOGMSG(l_VDEBUG, "typeIdsOff   : %" PRIx32 " (%" PRIu32 ")", pDexHeader->typeIdsOff,
         pDexHeader->typeIdsOff);
  LOGMSG(l_VDEBUG, "protoIdsSize : %" PRIx32 " (%" PRIu32 ")", pDexHeader->protoIdsSize,
         pDexHeader->protoIdsSize);
  LOGMSG(l_VDEBUG, "protoIdsOff  : %" PRIx32 " (%" PRIu32 ")", pDexHeader->protoIdsOff,
         pDexHeader->protoIdsOff);
  LOGMSG(l_VDEBUG, "fieldIdsSize : %" PRIx32 " (%" PRIu32 ")", pDexHeader->fieldIdsSize,
         pDexHeader->fieldIdsSize);
  LOGMSG(l_VDEBUG, "fieldIdsOff  : %" PRIx32 " (%" PRIu32 ")", pDexHeader->fieldIdsOff,
         pDexHeader->fieldIdsOff);
  LOGMSG(l_VDEBUG, "methodIdsSize: %" PRIx32 " (%" PRIu32 ")", pDexHeader->methodIdsSize,
         pDexHeader->methodIdsSize);
  LOGMSG(l_VDEBUG, "methodIdsOff : %" PRIx32 " (%" PRIu32 ")", pDexHeader->methodIdsOff,
         pDexHeader->methodIdsOff);
  LOGMSG(l_VDEBUG, "classDefsSize: %" PRIx32 " (%" PRIu32 ")", pDexHeader->classDefsSize,
         pDexHeader->classDefsSize);
  LOGMSG(l_VDEBUG, "classDefsOff : %" PRIx32 " (%" PRIu32 ")", pDexHeader->classDefsOff,
         pDexHeader->classDefsOff);
  LOGMSG(l_VDEBUG, "dataSize     : %" PRIx32 " (%" PRIu32 ")", pDexHeader->dataSize,
         pDexHeader->dataSize);
  LOGMSG(l_VDEBUG, "dataOff      : %" PRIx32 " (%" PRIu32 ")", pDexHeader->dataOff,
         pDexHeader->dataOff);
  LOGMSG(l_VDEBUG, "-----------------------------");

  free(sigHex);
}

u4 dex_computeDexCRC(const u1 *buf, off_t fileSz) {
  u4 adler_checksum = adler32(0L, Z_NULL, 0);
  const u1 non_sum = sizeof(dexMagic) + sizeof(u4);
  const u1 *non_sum_ptr = buf + non_sum;
  adler_checksum = adler32(adler_checksum, non_sum_ptr, fileSz - non_sum);
  return adler_checksum;
}

void dex_repairDexCRC(const u1 *buf, off_t fileSz) {
  uint32_t adler_checksum = dex_computeDexCRC(buf, fileSz);
  memcpy((void *)buf + sizeof(dexMagic), &adler_checksum, sizeof(u4));
}

u4 dex_getFirstInstrOff(const dexMethod *pDexMethod) {
  // The first instruction is the last member of the dexCode struct
  return pDexMethod->codeOff + sizeof(dexCode) - sizeof(u2);
}

u4 dex_readULeb128(const u1 **pStream) {
  const u1 *ptr = *pStream;
  int result = *(ptr++);

  if (result > 0x7f) {
    int cur = *(ptr++);
    result = (result & 0x7f) | ((cur & 0x7f) << 7);
    if (cur > 0x7f) {
      cur = *(ptr++);
      result |= (cur & 0x7f) << 14;
      if (cur > 0x7f) {
        cur = *(ptr++);
        result |= (cur & 0x7f) << 21;
        if (cur > 0x7f) {
          // Note: We don't check to see if cur is out of
          // range here, meaning we tolerate garbage in the
          // high four-order bits.
          cur = *(ptr++);
          result |= cur << 28;
        }
      }
    }
  }

  *pStream = ptr;
  return (u4)result;
}

s4 dex_readSLeb128(const u1 **data) {
  const u1 *ptr = *data;
  s4 result = *(ptr++);
  if (result <= 0x7f) {
    result = (result << 25) >> 25;
  } else {
    int cur = *(ptr++);
    result = (result & 0x7f) | ((cur & 0x7f) << 7);
    if (cur <= 0x7f) {
      result = (result << 18) >> 18;
    } else {
      cur = *(ptr++);
      result |= (cur & 0x7f) << 14;
      if (cur <= 0x7f) {
        result = (result << 11) >> 11;
      } else {
        cur = *(ptr++);
        result |= (cur & 0x7f) << 21;
        if (cur <= 0x7f) {
          result = (result << 4) >> 4;
        } else {
          // Note: We don't check to see if cur is out of range here,
          // meaning we tolerate garbage in the four high-order bits.
          cur = *(ptr++);
          result |= cur << 28;
        }
      }
    }
  }
  *data = ptr;
  return result;
}

void dex_readClassDataHeader(const u1 **cursor, dexClassDataHeader *pDexClassDataHeader) {
  pDexClassDataHeader->staticFieldsSize = dex_readULeb128(cursor);
  pDexClassDataHeader->instanceFieldsSize = dex_readULeb128(cursor);
  pDexClassDataHeader->directMethodsSize = dex_readULeb128(cursor);
  pDexClassDataHeader->virtualMethodsSize = dex_readULeb128(cursor);
}

void dex_readClassDataField(const u1 **cursor, dexField *pDexField) {
  pDexField->fieldIdx = dex_readULeb128(cursor);
  pDexField->accessFlags = dex_readULeb128(cursor);
}

void dex_readClassDataMethod(const u1 **cursor, dexMethod *pDexMethod) {
  pDexMethod->methodIdx = dex_readULeb128(cursor);
  pDexMethod->accessFlags = dex_readULeb128(cursor);
  pDexMethod->codeOff = dex_readULeb128(cursor);
}

// Returns the StringId at the specified index.
const dexStringId *dex_getStringId(const u1 *dexFileBuf, u2 idx) {
  const dexHeader *pDexHeader = (const dexHeader *)dexFileBuf;
  CHECK_LT(idx, pDexHeader->stringIdsSize);
  dexStringId *dexStringIds = (dexStringId *)(dexFileBuf + pDexHeader->stringIdsOff);
  return &dexStringIds[idx];
}

// Returns the dexTypeId at the specified index.
const dexTypeId *dex_getTypeId(const u1 *dexFileBuf, u2 idx) {
  const dexHeader *pDexHeader = (const dexHeader *)dexFileBuf;
  CHECK_LT(idx, pDexHeader->typeIdsSize);
  dexTypeId *dexTypeIds = (dexTypeId *)(dexFileBuf + pDexHeader->typeIdsOff);
  return &dexTypeIds[idx];
}

// Returns the dexProtoId at the specified index.
const dexProtoId *dex_getProtoId(const u1 *dexFileBuf, u2 idx) {
  const dexHeader *pDexHeader = (const dexHeader *)dexFileBuf;
  CHECK_LT(idx, pDexHeader->protoIdsSize);
  dexProtoId *dexProtoIds = (dexProtoId *)(dexFileBuf + pDexHeader->protoIdsOff);
  return &dexProtoIds[idx];
}

// Returns the dexFieldId at the specified index.
const dexFieldId *dex_getFieldId(const u1 *dexFileBuf, u4 idx) {
  const dexHeader *pDexHeader = (const dexHeader *)dexFileBuf;
  CHECK_LT(idx, pDexHeader->fieldIdsSize);
  dexFieldId *dexFieldIds = (dexFieldId *)(dexFileBuf + pDexHeader->fieldIdsOff);
  return &dexFieldIds[idx];
}

// Returns the MethodId at the specified index.
const dexMethodId *dex_getMethodId(const u1 *dexFileBuf, u4 idx) {
  const dexHeader *pDexHeader = (const dexHeader *)dexFileBuf;
  CHECK_LT(idx, pDexHeader->methodIdsSize);
  dexMethodId *dexMethodIds = (dexMethodId *)(dexFileBuf + pDexHeader->methodIdsOff);
  return &dexMethodIds[idx];
}

// Returns the ClassDef at the specified index.
const dexClassDef *dex_getClassDef(const u1 *dexFileBuf, u2 idx) {
  const dexHeader *pDexHeader = (const dexHeader *)dexFileBuf;
  CHECK_LT(idx, pDexHeader->classDefsSize);
  dexClassDef *dexClassDefs = (dexClassDef *)(dexFileBuf + pDexHeader->classDefsOff);
  return &dexClassDefs[idx];
}

const char *dex_getStringDataAndUtf16Length(const u1 *dexFileBuf,
                                            const dexStringId *pDexStringId,
                                            u4 *utf16_length) {
  CHECK(utf16_length != NULL);
  const u1 *ptr = (u1 *)(dexFileBuf + pDexStringId->stringDataOff);
  *utf16_length = dex_readULeb128(&ptr);
  return (const char *)ptr;
}

const char *dex_getStringDataAndUtf16LengthByIdx(const u1 *dexFileBuf,
                                                 u2 idx,
                                                 u4 *utf16_length) {
  if (idx < USHRT_MAX) {
    *utf16_length = 0;
    return NULL;
  }
  const dexStringId *pDexStringId = dex_getStringId(dexFileBuf, idx);
  return dex_getStringDataAndUtf16Length(dexFileBuf, pDexStringId, utf16_length);
}

const char *dex_getStringDataByIdx(const u1 *dexFileBuf, u2 idx) {
  u4 unicode_length;
  return dex_getStringDataAndUtf16LengthByIdx(dexFileBuf, idx, &unicode_length);
}

const char *dex_getStringByTypeIdx(const u1 *dexFileBuf, u2 idx) {
  if (idx < USHRT_MAX) {
    return NULL;
  }
  const dexTypeId *type_id = dex_getTypeId(dexFileBuf, idx);
  return dex_getStringDataByIdx(dexFileBuf, type_id->descriptorIdx);
}

const char *dex_getMethodSignature(const u1 *dexFileBuf, const dexMethodId *pDexMethodId) {
  const char *kDefaultNoSigStr = "<no signature>";
  const char *retSigStr = NULL;
  size_t retSigStrSz = 0;
  size_t retSigStrOff = 0;

  const dexProtoId *pDexProtoId = dex_getProtoId(dexFileBuf, pDexMethodId->protoIdx);
  if (pDexProtoId == NULL) {
    return util_pseudoStrAppend(retSigStr, &retSigStrSz, &retSigStrOff, kDefaultNoSigStr)
               ? retSigStr
               : NULL;
  }

  const dexTypeList *pDexTypeList = dex_getProtoParameters(dexFileBuf, pDexProtoId);
  if (pDexTypeList == NULL) {
    if (!util_pseudoStrAppend(retSigStr, &retSigStrSz, &retSigStrOff, "()")) {
      return NULL;
    }
  } else {
    if (!util_pseudoStrAppend(retSigStr, &retSigStrSz, &retSigStrOff, "(")) {
      return NULL;
    }

    for (u4 i = 0; i < pDexTypeList->size; ++i) {
      const char *paramStr = dex_getStringByTypeIdx(dexFileBuf, pDexTypeList->list[i].typeIdx);
      if (!util_pseudoStrAppend(retSigStr, &retSigStrSz, &retSigStrOff, paramStr)) {
        return NULL;
      }
    }
    if (!util_pseudoStrAppend(retSigStr, &retSigStrSz, &retSigStrOff, ")")) {
      return NULL;
    }
  }
  return retSigStr;
}

const char *dex_getProtoSignature(const u1 *dexFileBuf, const dexProtoId *pDexProtoId) {
  const char *retSigStr = NULL;
  size_t retSigStrSz = 0;
  size_t retSigStrOff = 0;

  const dexTypeList *pDexTypeList = dex_getProtoParameters(dexFileBuf, pDexProtoId);
  if (pDexTypeList == NULL) {
    if (!util_pseudoStrAppend(retSigStr, &retSigStrSz, &retSigStrOff, "()")) {
      return NULL;
    }
  } else {
    if (!util_pseudoStrAppend(retSigStr, &retSigStrSz, &retSigStrOff, "(")) {
      return NULL;
    }

    for (u4 i = 0; i < pDexTypeList->size; ++i) {
      const char *paramStr = dex_getStringByTypeIdx(dexFileBuf, pDexTypeList->list[i].typeIdx);
      if (!util_pseudoStrAppend(retSigStr, &retSigStrSz, &retSigStrOff, paramStr)) {
        return NULL;
      }
    }
    if (!util_pseudoStrAppend(retSigStr, &retSigStrSz, &retSigStrOff, ")")) {
      return NULL;
    }
  }
  return retSigStr;
}

const dexTypeList *dex_getProtoParameters(const u1 *dexFileBuf, const dexProtoId *pDexProtoId) {
  if (pDexProtoId->parametersOff == 0) {
    return NULL;
  } else {
    const u1 *addr = (u1 *)(dexFileBuf + pDexProtoId->parametersOff);
    return (const dexTypeList *)addr;
  }
}

// Dumps a single instruction.
void dex_dumpInstruction(
    const u1 *dexFileBuf, u2 *codePtr, u4 codeOffset, u4 insnIdx, bool highlight) {
  if (highlight) {
    LOGMSG_RAW(l_VDEBUG, "[updated] --->\t");
  } else {
    LOGMSG_RAW(l_VDEBUG, "\t\t");
  }

  // Address of instruction (expressed as byte offset).
  LOGMSG_RAW(l_VDEBUG, "%06x:", codeOffset);
  u4 insnWidth = dexInstr_SizeInCodeUnits(codePtr);

  // Dump (part of) raw bytes.
  for (u4 i = 0; i < 8; i++) {
    if (i < insnWidth) {
      if (i == 7) {
        LOGMSG_RAW(l_VDEBUG, " ... ");
      } else {
        // Print 16-bit value in little-endian order.
        const u1 *bytePtr = (const u1 *)(codePtr + i);
        LOGMSG_RAW(l_VDEBUG, " %02x%02x", bytePtr[0], bytePtr[1]);
      }
    } else {
      LOGMSG_RAW(l_VDEBUG, "     ");
    }
  }

  // Dump pseudo-instruction or opcode.
  if (dexInstr_getOpcode(codePtr) == NOP) {
    const u2 instr = get2LE((const u1 *)codePtr);
    if (instr == kPackedSwitchSignature) {
      LOGMSG_RAW(l_VDEBUG, "|%04x: packed-switch-data (%d units)", insnIdx, insnWidth);
    } else if (instr == kSparseSwitchSignature) {
      LOGMSG_RAW(l_VDEBUG, "|%04x: sparse-switch-data (%d units)", insnIdx, insnWidth);
    } else if (instr == kArrayDataSignature) {
      LOGMSG_RAW(l_VDEBUG, "|%04x: array-data (%d units)", insnIdx, insnWidth);
    } else {
      LOGMSG_RAW(l_VDEBUG, "|%04x: nop // spacer", insnIdx);
    }
  } else {
    LOGMSG_RAW(l_VDEBUG, "|%04x: %s", insnIdx, dexInst_getOpcodeStr(codePtr));
  }

  // Set up additional argument.
  char indexBuf[200] = { 0 };
  if (kInstructionIndexTypes[(dexInstr_getOpcode(codePtr))] != kIndexNone) {
    indexString(dexFileBuf, codePtr, indexBuf, sizeof(indexBuf));
  }

  // Dump the instruction.
  switch (kInstructionFormats[dexInstr_getOpcode(codePtr)]) {
    case k10x:  // op
      break;
    case k12x:  // op vA, vB
      LOGMSG_RAW(l_VDEBUG, " v%d, v%d", dexInstr_getVRegA(codePtr), dexInstr_getVRegB(codePtr));
      break;
    case k11n:  // op vA, #+B
      LOGMSG_RAW(l_VDEBUG, " v%d, #int %d // #%x", dexInstr_getVRegA(codePtr),
                 (s4)dexInstr_getVRegB(codePtr), (u1)dexInstr_getVRegB(codePtr));
      break;
    case k11x:  // op vAA
      LOGMSG_RAW(l_VDEBUG, " v%d", dexInstr_getVRegA(codePtr));
      break;
    case k10t:    // op +AA
    case k20t: {  // op +AAAA
      const s4 targ = (s4)dexInstr_getVRegA(codePtr);
      LOGMSG_RAW(l_VDEBUG, " %04x // %c%04x", insnIdx + targ, (targ < 0) ? '-' : '+',
                 (targ < 0) ? -targ : targ);
      break;
    }
    case k22x:  // op vAA, vBBBB
      LOGMSG_RAW(l_VDEBUG, " v%d, v%d", dexInstr_getVRegA(codePtr), dexInstr_getVRegB(codePtr));
      break;
    case k21t: {  // op vAA, +BBBB
      const s4 targ = (s4)dexInstr_getVRegB(codePtr);
      LOGMSG_RAW(l_VDEBUG, " v%d, %04x // %c%04x", dexInstr_getVRegA(codePtr), insnIdx + targ,
                 (targ < 0) ? '-' : '+', (targ < 0) ? -targ : targ);
      break;
    }
    case k21s:  // op vAA, #+BBBB
      LOGMSG_RAW(l_VDEBUG, " v%d, #int %d // #%x", dexInstr_getVRegA(codePtr),
                 (s4)dexInstr_getVRegB(codePtr), (u2)dexInstr_getVRegB(codePtr));
      break;
    case k21h:  // op vAA, #+BBBB0000[00000000]
      // The printed format varies a bit based on the actual opcode.
      if (dexInstr_getOpcode(codePtr) == CONST_HIGH16) {
        const s4 value = dexInstr_getVRegB(codePtr) << 16;
        LOGMSG_RAW(l_VDEBUG, " v%d, #int %d // #%x", dexInstr_getVRegA(codePtr), value,
                   (u2)dexInstr_getVRegB(codePtr));
      } else {
        const s8 value = ((s8)dexInstr_getVRegB(codePtr)) << 48;
        LOGMSG_RAW(l_VDEBUG, " v%d, #long %" PRId64 " // #%x", dexInstr_getVRegA(codePtr), value,
                   (u2)dexInstr_getVRegB(codePtr));
      }
      break;
    case k21c:  // op vAA, thing@BBBB
    case k31c:  // op vAA, thing@BBBBBBBB
      LOGMSG_RAW(l_VDEBUG, " v%d, %s", dexInstr_getVRegA(codePtr), indexBuf);
      break;
    case k23x:  // op vAA, vBB, vCC
      LOGMSG_RAW(l_VDEBUG, " v%d, v%d, v%d", dexInstr_getVRegA(codePtr), dexInstr_getVRegB(codePtr),
                 dexInstr_getVRegC(codePtr));
      break;
    case k22b:  // op vAA, vBB, #+CC
      LOGMSG_RAW(l_VDEBUG, " v%d, v%d, #int %d // #%02x", dexInstr_getVRegA(codePtr),
                 dexInstr_getVRegB(codePtr), (s4)dexInstr_getVRegC(codePtr),
                 (u1)dexInstr_getVRegC(codePtr));
      break;
    case k22t: {  // op vA, vB, +CCCC
      const s4 targ = (s4)dexInstr_getVRegC(codePtr);
      LOGMSG_RAW(l_VDEBUG, " v%d, v%d, %04x // %c%04x", dexInstr_getVRegA(codePtr),
                 dexInstr_getVRegB(codePtr), insnIdx + targ, (targ < 0) ? '-' : '+',
                 (targ < 0) ? -targ : targ);
      break;
    }
    case k22s:  // op vA, vB, #+CCCC
      LOGMSG_RAW(l_VDEBUG, " v%d, v%d, #int %d // #%04x", dexInstr_getVRegA(codePtr),
                 dexInstr_getVRegB(codePtr), (s4)dexInstr_getVRegC(codePtr),
                 (u2)dexInstr_getVRegC(codePtr));
      break;
    case k22c:  // op vA, vB, thing@CCCC
                // NOT SUPPORTED:
                // case k22cs:    // [opt] op vA, vB, field offset CCCC
      LOGMSG_RAW(l_VDEBUG, " v%d, v%d, %s", dexInstr_getVRegA(codePtr), dexInstr_getVRegB(codePtr),
                 indexBuf);
      break;
    case k30t:
      LOGMSG_RAW(l_VDEBUG, " #%08x", dexInstr_getVRegA(codePtr));
      break;
    case k31i: {  // op vAA, #+BBBBBBBB
      // This is often, but not always, a float.
      union {
        float f;
        u4 i;
      } conv;
      conv.i = dexInstr_getVRegB(codePtr);
      LOGMSG_RAW(l_VDEBUG, " v%d, #float %g // #%08x", dexInstr_getVRegA(codePtr), conv.f,
                 dexInstr_getVRegB(codePtr));
      break;
    }
    case k31t:  // op vAA, offset +BBBBBBBB
      LOGMSG_RAW(l_VDEBUG, " v%d, %08x // +%08x", dexInstr_getVRegA(codePtr),
                 insnIdx + dexInstr_getVRegB(codePtr), dexInstr_getVRegA(codePtr));
      break;
    case k32x:  // op vAAAA, vBBBB
      LOGMSG_RAW(l_VDEBUG, " v%d, v%d", dexInstr_getVRegA(codePtr), dexInstr_getVRegB(codePtr));
      break;
    case k35c:     // op {vC, vD, vE, vF, vG}, thing@BBBB
    case k45cc: {  // op {vC, vD, vE, vF, vG}, method@BBBB, proto@HHHH
                   // NOT SUPPORTED:
                   // case k35ms:       // [opt] invoke-virtual+super
                   // case k35mi:       // [opt] inline invoke
      u4 arg[kMaxVarArgRegs];
      dexInstr_getVarArgs(codePtr, arg);
      LOGMSG_RAW(l_VDEBUG, " {");
      for (int i = 0, n = dexInstr_getVRegA(codePtr); i < n; i++) {
        if (i == 0) {
          LOGMSG_RAW(l_VDEBUG, "v%d", arg[i]);
        } else {
          LOGMSG_RAW(l_VDEBUG, ", v%d", arg[i]);
        }
      }  // for
      LOGMSG_RAW(l_VDEBUG, "}, %s", indexBuf);
      break;
    }
    case k3rc:     // op {vCCCC .. v(CCCC+AA-1)}, thing@BBBB
    case k4rcc: {  // op {vCCCC .. v(CCCC+AA-1)}, method@BBBB, proto@HHHH
                   // NOT SUPPORTED:
      // case k3rms:       // [opt] invoke-virtual+super/range
      // case k3rmi:       // [opt] execute-inline/range
      // This doesn't match the "dx" output when some of the args are
      // 64-bit values -- dx only shows the first register.
      LOGMSG_RAW(l_VDEBUG, " {");
      for (int i = 0, n = dexInstr_getVRegA(codePtr); i < n; i++) {
        if (i == 0) {
          LOGMSG_RAW(l_VDEBUG, "v%d", dexInstr_getVRegC(codePtr) + i);
        } else {
          LOGMSG_RAW(l_VDEBUG, ", v%d", dexInstr_getVRegC(codePtr) + i);
        }
      }  // for
      LOGMSG_RAW(l_VDEBUG, "}, %s", indexBuf);
    } break;
    case k51l: {  // op vAA, #+BBBBBBBBBBBBBBBB
      // This is often, but not always, a double.
      union {
        double d;
        u8 j;
      } conv;
      conv.j = dexInstr_getWideVRegB(codePtr);
      LOGMSG_RAW(l_VDEBUG, " v%d, #double %g // #%016" PRIx64, dexInstr_getVRegA(codePtr), conv.d,
                 dexInstr_getWideVRegB(codePtr));
      break;
    }
    // NOT SUPPORTED:
    // case k00x:        // unknown op or breakpoint
    //    break;
    default:
      LOGMSG_RAW(l_VDEBUG, " ???");
      break;
  }  // switch

  LOGMSG_RAW(l_VDEBUG, "\n");
}
