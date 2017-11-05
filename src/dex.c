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

static bool enableDisassembler = false;
static bool enableClassRecover = false;

static inline u2 get2LE(unsigned char const *pSrc) { return pSrc[0] | (pSrc[1] << 8); }

// Helper for dex_dumpInstruction(), which builds the string representation
// for the index in the given instruction.
static char *indexString(const u1 *dexFileBuf, u2 *codePtr, u4 bufSize) {
  char *buf = utils_calloc(bufSize);

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
        free((void *)signature);
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
      const char *kDefaultMethodStr = "<method?>";
      const char *kDefaultProtoStr = "<proto?>";
      const char *methodStr = utils_calloc(32);
      const char *protoStr = utils_calloc(32);
      strncpy((void *)methodStr, kDefaultMethodStr, strlen(kDefaultMethodStr));
      strncpy((void *)protoStr, kDefaultProtoStr, strlen(kDefaultProtoStr));

      if (index < pDexHeader->methodIdsSize) {
        const dexMethodId *pDexMethodId = dex_getMethodId(dexFileBuf, index);
        const char *name = dex_getStringDataByIdx(dexFileBuf, pDexMethodId->nameIdx);
        const char *signature = dex_getMethodSignature(dexFileBuf, pDexMethodId);
        const char *backDescriptor = dex_getStringByTypeIdx(dexFileBuf, pDexMethodId->classIdx);

        // Free the default and allocate a new one
        free((void *)methodStr);
        size_t newMethodStrSz = strlen(backDescriptor) + strlen(name) + strlen(signature) + 3;
        methodStr = utils_calloc(newMethodStrSz);
        snprintf((char *)methodStr, newMethodStrSz, "%s.%s:%s", backDescriptor, name, signature);

        // Clean-up intermediates
        free((void *)signature);
      }
      if (secondary_index < pDexHeader->protoIdsSize) {
        const dexProtoId *pDexProtoId = dex_getProtoId(dexFileBuf, secondary_index);

        // Free the default since a new one is allocated
        free((void *)protoStr);
        protoStr = dex_getProtoSignature(dexFileBuf, pDexProtoId);
      }

      outSize = snprintf(buf, bufSize, "%s, %s // method@%0*x, proto@%0*x", methodStr, protoStr,
                         width, index, width, secondary_index);
      free((void *)methodStr);
      free((void *)protoStr);
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
    // The buffer wasn't big enough, try with new size + null termination
    free(buf);
    size_t newBufSz = outSize + 1;
    return indexString(dexFileBuf, codePtr, newBufSz);
  }
  return buf;
}

// Converts a single-character primitive type into human-readable form.
static const char *primitiveTypeLabel(char typeChar) {
  switch (typeChar) {
    case 'B':
      return "byte";
    case 'C':
      return "char";
    case 'D':
      return "double";
    case 'F':
      return "float";
    case 'I':
      return "int";
    case 'J':
      return "long";
    case 'S':
      return "short";
    case 'V':
      return "void";
    case 'Z':
      return "boolean";
    default:
      return "UNKNOWN";
  }
}

// Counts the number of '1' bits in a word.
static int countOnes(u4 val) {
  val = val - ((val >> 1) & 0x55555555);
  val = (val & 0x33333333) + ((val >> 2) & 0x33333333);
  return (((val + (val >> 4)) & 0x0F0F0F0F) * 0x01010101) >> 24;
}

// Creates a new string with human-readable access flags.
static char *createAccessFlagStr(u4 flags, dexAccessFor forWhat) {
  static const char *kAccessStrings[kDexAccessForMAX][kDexNumAccessFlags] = {
    {
        "PUBLIC",     /* 0x00001 */
        "PRIVATE",    /* 0x00002 */
        "PROTECTED",  /* 0x00004 */
        "STATIC",     /* 0x00008 */
        "FINAL",      /* 0x00010 */
        "?",          /* 0x00020 */
        "?",          /* 0x00040 */
        "?",          /* 0x00080 */
        "?",          /* 0x00100 */
        "INTERFACE",  /* 0x00200 */
        "ABSTRACT",   /* 0x00400 */
        "?",          /* 0x00800 */
        "SYNTHETIC",  /* 0x01000 */
        "ANNOTATION", /* 0x02000 */
        "ENUM",       /* 0x04000 */
        "?",          /* 0x08000 */
        "VERIFIED",   /* 0x10000 */
        "OPTIMIZED",  /* 0x20000 */
    },
    {
        "PUBLIC",                /* 0x00001 */
        "PRIVATE",               /* 0x00002 */
        "PROTECTED",             /* 0x00004 */
        "STATIC",                /* 0x00008 */
        "FINAL",                 /* 0x00010 */
        "SYNCHRONIZED",          /* 0x00020 */
        "BRIDGE",                /* 0x00040 */
        "VARARGS",               /* 0x00080 */
        "NATIVE",                /* 0x00100 */
        "?",                     /* 0x00200 */
        "ABSTRACT",              /* 0x00400 */
        "STRICT",                /* 0x00800 */
        "SYNTHETIC",             /* 0x01000 */
        "?",                     /* 0x02000 */
        "?",                     /* 0x04000 */
        "MIRANDA",               /* 0x08000 */
        "CONSTRUCTOR",           /* 0x10000 */
        "DECLARED_SYNCHRONIZED", /* 0x20000 */
    },
    {
        "PUBLIC",    /* 0x00001 */
        "PRIVATE",   /* 0x00002 */
        "PROTECTED", /* 0x00004 */
        "STATIC",    /* 0x00008 */
        "FINAL",     /* 0x00010 */
        "?",         /* 0x00020 */
        "VOLATILE",  /* 0x00040 */
        "TRANSIENT", /* 0x00080 */
        "?",         /* 0x00100 */
        "?",         /* 0x00200 */
        "?",         /* 0x00400 */
        "?",         /* 0x00800 */
        "SYNTHETIC", /* 0x01000 */
        "?",         /* 0x02000 */
        "ENUM",      /* 0x04000 */
        "?",         /* 0x08000 */
        "?",         /* 0x10000 */
        "?",         /* 0x20000 */
    },
  };

  // Allocate enough storage to hold the expected number of strings,
  // plus a space between each.  We over-allocate, using the longest
  // string above as the base metric.
  const int kLongest = 21;  // The strlen of longest string above.
  const int count = countOnes(flags);
  char *str;
  char *cp;
  cp = str = (char *)utils_malloc(count * (kLongest + 1) + 1);

  for (int i = 0; i < kDexNumAccessFlags; i++) {
    if (flags & 0x01) {
      const char *accessStr = kAccessStrings[forWhat][i];
      const int len = strlen(accessStr);
      if (cp != str) {
        *cp++ = ' ';
      }
      memcpy(cp, accessStr, len);
      cp += len;
    }
    flags >>= 1;
  }  // for

  *cp = '\0';
  return str;
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
  char *sigHex = utils_bin2hex(pDexHeader->signature, kSHA1Len);

  log_dis("------ Dex Header Info ------\n");
  log_dis("magic        : %.3s-%.3s\n", pDexHeader->magic.dex, pDexHeader->magic.ver);
  log_dis("checksum     : %" PRIx32 " (%" PRIu32 ")\n", pDexHeader->checksum, pDexHeader->checksum);
  log_dis("signature    : %s", sigHex);
  log_dis("fileSize     : %" PRIx32 " (%" PRIu32 ")\n", pDexHeader->fileSize, pDexHeader->fileSize);
  log_dis("headerSize   : %" PRIx32 " (%" PRIu32 ")\n", pDexHeader->headerSize,
          pDexHeader->headerSize);
  log_dis("endianTag    : %" PRIx32 " (%" PRIu32 ")\n", pDexHeader->endianTag,
          pDexHeader->endianTag);
  log_dis("linkSize     : %" PRIx32 " (%" PRIu32 ")\n", pDexHeader->linkSize, pDexHeader->linkSize);
  log_dis("linkOff      : %" PRIx32 " (%" PRIu32 ")\n", pDexHeader->linkOff, pDexHeader->linkOff);
  log_dis("mapOff       : %" PRIx32 " (%" PRIu32 ")\n", pDexHeader->mapOff, pDexHeader->mapOff);
  log_dis("stringIdsSize: %" PRIx32 " (%" PRIu32 ")\n", pDexHeader->stringIdsSize,
          pDexHeader->stringIdsSize);
  log_dis("stringIdsOff : %" PRIx32 " (%" PRIu32 ")\n", pDexHeader->stringIdsOff,
          pDexHeader->stringIdsOff);
  log_dis("typeIdsSize  : %" PRIx32 " (%" PRIu32 ")\n", pDexHeader->typeIdsSize,
          pDexHeader->typeIdsSize);
  log_dis("typeIdsOff   : %" PRIx32 " (%" PRIu32 ")\n", pDexHeader->typeIdsOff,
          pDexHeader->typeIdsOff);
  log_dis("protoIdsSize : %" PRIx32 " (%" PRIu32 ")\n", pDexHeader->protoIdsSize,
          pDexHeader->protoIdsSize);
  log_dis("protoIdsOff  : %" PRIx32 " (%" PRIu32 ")\n", pDexHeader->protoIdsOff,
          pDexHeader->protoIdsOff);
  log_dis("fieldIdsSize : %" PRIx32 " (%" PRIu32 ")\n", pDexHeader->fieldIdsSize,
          pDexHeader->fieldIdsSize);
  log_dis("fieldIdsOff  : %" PRIx32 " (%" PRIu32 ")\n", pDexHeader->fieldIdsOff,
          pDexHeader->fieldIdsOff);
  log_dis("methodIdsSize: %" PRIx32 " (%" PRIu32 ")\n", pDexHeader->methodIdsSize,
          pDexHeader->methodIdsSize);
  log_dis("methodIdsOff : %" PRIx32 " (%" PRIu32 ")\n", pDexHeader->methodIdsOff,
          pDexHeader->methodIdsOff);
  log_dis("classDefsSize: %" PRIx32 " (%" PRIu32 ")\n", pDexHeader->classDefsSize,
          pDexHeader->classDefsSize);
  log_dis("classDefsOff : %" PRIx32 " (%" PRIu32 ")\n", pDexHeader->classDefsOff,
          pDexHeader->classDefsOff);
  log_dis("dataSize     : %" PRIx32 " (%" PRIu32 ")\n", pDexHeader->dataSize, pDexHeader->dataSize);
  log_dis("dataOff      : %" PRIx32 " (%" PRIu32 ")\n", pDexHeader->dataOff, pDexHeader->dataOff);
  log_dis("-----------------------------\n");

  free((void *)sigHex);
}

u4 dex_computeDexCRC(const u1 *buf, off_t fileSz) {
  u4 adler_checksum = adler32(0L, Z_NULL, 0);
  const u1 non_sum = sizeof(dexMagic) + sizeof(u4);
  const u1 *non_sum_ptr = buf + non_sum;
  adler_checksum = adler32(adler_checksum, non_sum_ptr, fileSz - non_sum);
  return adler_checksum;
}

void dex_repairDexCRC(const u1 *buf, off_t fileSz) {
  u4 adler_checksum = dex_computeDexCRC(buf, fileSz);
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

const char *dex_getStringDataAndUtf16LengthByIdx(const u1 *dexFileBuf, u2 idx, u4 *utf16_length) {
  const dexStringId *pDexStringId = dex_getStringId(dexFileBuf, idx);
  return dex_getStringDataAndUtf16Length(dexFileBuf, pDexStringId, utf16_length);
}

const char *dex_getStringDataByIdx(const u1 *dexFileBuf, u2 idx) {
  u4 unicode_length;
  return dex_getStringDataAndUtf16LengthByIdx(dexFileBuf, idx, &unicode_length);
}

const char *dex_getStringByTypeIdx(const u1 *dexFileBuf, u2 idx) {
  const dexTypeId *type_id = dex_getTypeId(dexFileBuf, idx);
  return dex_getStringDataByIdx(dexFileBuf, type_id->descriptorIdx);
}

const char *dex_getMethodSignature(const u1 *dexFileBuf, const dexMethodId *pDexMethodId) {
  return dex_getProtoSignature(dexFileBuf, dex_getProtoId(dexFileBuf, pDexMethodId->protoIdx));
}

const char *dex_getProtoSignature(const u1 *dexFileBuf, const dexProtoId *pDexProtoId) {
  const char *retSigStr = NULL;
  size_t retSigStrSz = 0;
  size_t retSigStrOff = 0;

  if (pDexProtoId == NULL) {
    const char *kDefaultNoSigStr = "<no signature>";
    retSigStr = utils_calloc(strlen(kDefaultNoSigStr) + 1);
    strncpy((char *)retSigStr, kDefaultNoSigStr, strlen(kDefaultNoSigStr));
    return retSigStr;
  }

  const dexTypeList *pDexTypeList = dex_getProtoParameters(dexFileBuf, pDexProtoId);
  if (pDexTypeList == NULL) {
    utils_pseudoStrAppend(&retSigStr, &retSigStrSz, &retSigStrOff, "()");
  } else {
    utils_pseudoStrAppend(&retSigStr, &retSigStrSz, &retSigStrOff, "(");
    for (u4 i = 0; i < pDexTypeList->size; ++i) {
      const char *paramStr = dex_getStringByTypeIdx(dexFileBuf, pDexTypeList->list[i].typeIdx);
      utils_pseudoStrAppend(&retSigStr, &retSigStrSz, &retSigStrOff, paramStr);
    }
    utils_pseudoStrAppend(&retSigStr, &retSigStrSz, &retSigStrOff, ")");
  }

  const char *retTypeStr = dex_getStringByTypeIdx(dexFileBuf, pDexProtoId->returnTypeIdx);
  utils_pseudoStrAppend(&retSigStr, &retSigStrSz, &retSigStrOff, retTypeStr);

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

const char *dex_getFieldDeclaringClassDescriptor(const u1 *dexFileBuf,
                                                 const dexFieldId *pDexFieldId) {
  const dexTypeId *pDexTypeId = dex_getTypeId(dexFileBuf, pDexFieldId->classIdx);
  return dex_getTypeDescriptor(dexFileBuf, pDexTypeId);
}

const char *dex_getTypeDescriptor(const u1 *dexFileBuf, const dexTypeId *pDexTypeId) {
  return dex_getStringDataByIdx(dexFileBuf, pDexTypeId->descriptorIdx);
}

const char *dex_getFieldName(const u1 *dexFileBuf, const dexFieldId *pDexField) {
  return dex_getStringDataByIdx(dexFileBuf, pDexField->nameIdx);
}

const char *dex_getFieldTypeDescriptor(const u1 *dexFileBuf, const dexFieldId *pDexFieldId) {
  const dexTypeId *pDexTypeId = dex_getTypeId(dexFileBuf, pDexFieldId->typeIdx);
  return dex_getTypeDescriptor(dexFileBuf, pDexTypeId);
}

const char *dex_getMethodDeclaringClassDescriptor(const u1 *dexFileBuf,
                                                  const dexMethodId *pDexMethodId) {
  const dexTypeId *pDexTypeId = dex_getTypeId(dexFileBuf, pDexMethodId->classIdx);
  return dex_getTypeDescriptor(dexFileBuf, pDexTypeId);
}

const char *dex_getMethodName(const u1 *dexFileBuf, const dexMethodId *pDexMethodId) {
  return dex_getStringDataByIdx(dexFileBuf, pDexMethodId->nameIdx);
}

void dex_dumpClassInfo(const u1 *dexFileBuf, u4 idx) {
  const dexClassDef *pDexClassDef = dex_getClassDef(dexFileBuf, idx);
  const char *classDescriptor = dex_getStringByTypeIdx(dexFileBuf, pDexClassDef->classIdx);
  const char *classDescriptorFormated = dex_descriptorClassToDot(classDescriptor);
  const char *classAccessStr = createAccessFlagStr(pDexClassDef->accessFlags, kDexAccessForClass);
  const char *srcFileName = "<striped src file>";
  if (pDexClassDef->sourceFileIdx < USHRT_MAX) {
    srcFileName = dex_getStringDataByIdx(dexFileBuf, pDexClassDef->sourceFileIdx);
  }

  log_dis("  class #%" PRIu32 ": %s ('%s')\n", idx, classDescriptorFormated, classDescriptor);
  log_dis("   access=%04" PRIx32 " (%s)\n", pDexClassDef->accessFlags, classAccessStr);
  log_dis("   source_file=%s, class_data_off=%" PRIx32 " (%" PRIu32 ")\n", srcFileName,
          pDexClassDef->classDataOff, pDexClassDef->classDataOff);

  if (pDexClassDef->classDataOff != 0) {
    dexClassDataHeader pDexClassDataHeader;
    const u1 *curClassDataCursor = dexFileBuf + pDexClassDef->classDataOff;
    memset(&pDexClassDataHeader, 0, sizeof(dexClassDataHeader));
    dex_readClassDataHeader(&curClassDataCursor, &pDexClassDataHeader);
    log_dis("   static_fields=%" PRIu32 ", instance_fields=%" PRIu32 ", direct_methods=%" PRIu32
            ", virtual_methods=%" PRIu32 "\n",
            pDexClassDataHeader.staticFieldsSize, pDexClassDataHeader.instanceFieldsSize,
            pDexClassDataHeader.directMethodsSize, pDexClassDataHeader.virtualMethodsSize);
  }

  if (enableClassRecover) {
    const char *classDescriptorFormatedLong = dex_descriptorClassToDotLong(classDescriptor);
    log_clsRecWrite("    { \"name\": \"%s\", \"srcFileName\": \"%s\", ",
                    classDescriptorFormatedLong, srcFileName);
    free((void *)classDescriptorFormatedLong);
  }

  free((void *)classAccessStr);
  free((void *)classDescriptorFormated);
}

void dex_dumpMethodInfo(const u1 *dexFileBuf,
                        dexMethod *pDexMethod,
                        u4 localIdx,
                        const char *type) {
  const dexMethodId *pDexMethodId = dex_getMethodId(dexFileBuf, localIdx + pDexMethod->methodIdx);

  const char *methodName = dex_getStringDataByIdx(dexFileBuf, pDexMethodId->nameIdx);
  const char *typeDesc = dex_getMethodSignature(dexFileBuf, pDexMethodId);
  const char *methodAccessStr = createAccessFlagStr(pDexMethod->accessFlags, kDexAccessForMethod);

  log_dis("   %s_method #%" PRIu32 ": %s %s\n", type, localIdx, methodName, typeDesc);
  log_dis("    access=%04" PRIx32 " (%s)\n", pDexMethod->accessFlags, methodAccessStr);
  log_dis("    codeOff=%" PRIx32 " (%" PRIu32 ")\n", pDexMethod->codeOff, pDexMethod->codeOff);

  free((void *)methodAccessStr);
  free((void *)typeDesc);
}

void dex_dumpInstruction(const u1 *dexFileBuf,
                         u2 *codePtr,
                         u4 codeOffset,
                         u4 insnIdx,
                         bool highlight,
                         bool *foundLogUtilCall) {
  // Save time if no disassemble or no classRecover
  if (enableDisassembler == false && enableClassRecover == false) return;

  // Highlight decompile instructions
  if (highlight) {
    log_dis("[new] ");
  } else {
    log_dis("      ");
  }

  // Address of instruction (expressed as byte offset).
  log_dis("%06x:", codeOffset);
  u4 insnWidth = dexInstr_SizeInCodeUnits(codePtr);

  // Dump (part of) raw bytes.
  for (u4 i = 0; i < 8; i++) {
    if (i < insnWidth) {
      if (i == 7) {
        log_dis(" ... ");
      } else {
        // Print 16-bit value in little-endian order.
        const u1 *bytePtr = (const u1 *)(codePtr + i);
        log_dis(" %02x%02x", bytePtr[0], bytePtr[1]);
      }
    } else {
      log_dis("     ");
    }
  }

  // Dump pseudo-instruction or opcode.
  if (dexInstr_getOpcode(codePtr) == NOP) {
    const u2 instr = get2LE((const u1 *)codePtr);
    if (instr == kPackedSwitchSignature) {
      log_dis("|%04x: packed-switch-data (%d units)", insnIdx, insnWidth);
    } else if (instr == kSparseSwitchSignature) {
      log_dis("|%04x: sparse-switch-data (%d units)", insnIdx, insnWidth);
    } else if (instr == kArrayDataSignature) {
      log_dis("|%04x: array-data (%d units)", insnIdx, insnWidth);
    } else {
      log_dis("|%04x: nop // spacer", insnIdx);
    }
  } else {
    log_dis("|%04x: %s", insnIdx, dexInst_getOpcodeStr(codePtr));
  }

  // Set up additional argument.
  char *indexBuf = NULL;
  if (kInstructionIndexTypes[(dexInstr_getOpcode(codePtr))] != kIndexNone) {
    const size_t kDefaultIndexStrLen = 256;
    indexBuf = indexString(dexFileBuf, codePtr, kDefaultIndexStrLen);

    if (enableClassRecover && !*foundLogUtilCall && strstr(indexBuf, "Landroid/util/Log;.")) {
      log_clsRecWrite("\"callsLogUtil\": true");
      *foundLogUtilCall = true;
    }
  }

  // Dump the instruction.
  switch (kInstructionFormats[dexInstr_getOpcode(codePtr)]) {
    case k10x:  // op
      break;
    case k12x:  // op vA, vB
      log_dis(" v%d, v%d", dexInstr_getVRegA(codePtr), dexInstr_getVRegB(codePtr));
      break;
    case k11n:  // op vA, #+B
      log_dis(" v%d, #int %d // #%x", dexInstr_getVRegA(codePtr), (s4)dexInstr_getVRegB(codePtr),
              (u1)dexInstr_getVRegB(codePtr));
      break;
    case k11x:  // op vAA
      log_dis(" v%d", dexInstr_getVRegA(codePtr));
      break;
    case k10t:    // op +AA
    case k20t: {  // op +AAAA
      const s4 targ = (s4)dexInstr_getVRegA(codePtr);
      log_dis(" %04x // %c%04x", insnIdx + targ, (targ < 0) ? '-' : '+', (targ < 0) ? -targ : targ);
      break;
    }
    case k22x:  // op vAA, vBBBB
      log_dis(" v%d, v%d", dexInstr_getVRegA(codePtr), dexInstr_getVRegB(codePtr));
      break;
    case k21t: {  // op vAA, +BBBB
      const s4 targ = (s4)dexInstr_getVRegB(codePtr);
      log_dis(" v%d, %04x // %c%04x", dexInstr_getVRegA(codePtr), insnIdx + targ,
              (targ < 0) ? '-' : '+', (targ < 0) ? -targ : targ);
      break;
    }
    case k21s:  // op vAA, #+BBBB
      log_dis(" v%d, #int %d // #%x", dexInstr_getVRegA(codePtr), (s4)dexInstr_getVRegB(codePtr),
              (u2)dexInstr_getVRegB(codePtr));
      break;
    case k21h:  // op vAA, #+BBBB0000[00000000]
      // The printed format varies a bit based on the actual opcode.
      if (dexInstr_getOpcode(codePtr) == CONST_HIGH16) {
        const s4 value = dexInstr_getVRegB(codePtr) << 16;
        log_dis(" v%d, #int %d // #%x", dexInstr_getVRegA(codePtr), value,
                (u2)dexInstr_getVRegB(codePtr));
      } else {
        const s8 value = ((s8)dexInstr_getVRegB(codePtr)) << 48;
        log_dis(" v%d, #long %" PRId64 " // #%x", dexInstr_getVRegA(codePtr), value,
                (u2)dexInstr_getVRegB(codePtr));
      }
      break;
    case k21c:  // op vAA, thing@BBBB
    case k31c:  // op vAA, thing@BBBBBBBB
      log_dis(" v%d, %s", dexInstr_getVRegA(codePtr), indexBuf);
      break;
    case k23x:  // op vAA, vBB, vCC
      log_dis(" v%d, v%d, v%d", dexInstr_getVRegA(codePtr), dexInstr_getVRegB(codePtr),
              dexInstr_getVRegC(codePtr));
      break;
    case k22b:  // op vAA, vBB, #+CC
      log_dis(" v%d, v%d, #int %d // #%02x", dexInstr_getVRegA(codePtr), dexInstr_getVRegB(codePtr),
              (s4)dexInstr_getVRegC(codePtr), (u1)dexInstr_getVRegC(codePtr));
      break;
    case k22t: {  // op vA, vB, +CCCC
      const s4 targ = (s4)dexInstr_getVRegC(codePtr);
      log_dis(" v%d, v%d, %04x // %c%04x", dexInstr_getVRegA(codePtr), dexInstr_getVRegB(codePtr),
              insnIdx + targ, (targ < 0) ? '-' : '+', (targ < 0) ? -targ : targ);
      break;
    }
    case k22s:  // op vA, vB, #+CCCC
      log_dis(" v%d, v%d, #int %d // #%04x", dexInstr_getVRegA(codePtr), dexInstr_getVRegB(codePtr),
              (s4)dexInstr_getVRegC(codePtr), (u2)dexInstr_getVRegC(codePtr));
      break;
    case k22c:  // op vA, vB, thing@CCCC
                // NOT SUPPORTED:
                // case k22cs:    // [opt] op vA, vB, field offset CCCC
      log_dis(" v%d, v%d, %s", dexInstr_getVRegA(codePtr), dexInstr_getVRegB(codePtr), indexBuf);
      break;
    case k30t:
      log_dis(" #%08x", dexInstr_getVRegA(codePtr));
      break;
    case k31i: {  // op vAA, #+BBBBBBBB
      // This is often, but not always, a float.
      union {
        float f;
        u4 i;
      } conv;
      conv.i = dexInstr_getVRegB(codePtr);
      log_dis(" v%d, #float %g // #%08x", dexInstr_getVRegA(codePtr), conv.f,
              dexInstr_getVRegB(codePtr));
      break;
    }
    case k31t:  // op vAA, offset +BBBBBBBB
      log_dis(" v%d, %08x // +%08x", dexInstr_getVRegA(codePtr),
              insnIdx + dexInstr_getVRegB(codePtr), dexInstr_getVRegA(codePtr));
      break;
    case k32x:  // op vAAAA, vBBBB
      log_dis(" v%d, v%d", dexInstr_getVRegA(codePtr), dexInstr_getVRegB(codePtr));
      break;
    case k35c:     // op {vC, vD, vE, vF, vG}, thing@BBBB
    case k45cc: {  // op {vC, vD, vE, vF, vG}, method@BBBB, proto@HHHH
                   // NOT SUPPORTED:
                   // case k35ms:       // [opt] invoke-virtual+super
                   // case k35mi:       // [opt] inline invoke
      u4 arg[kMaxVarArgRegs];
      dexInstr_getVarArgs(codePtr, arg);
      log_dis(" {");
      for (int i = 0, n = dexInstr_getVRegA(codePtr); i < n; i++) {
        if (i == 0) {
          log_dis("v%d", arg[i]);
        } else {
          log_dis(", v%d", arg[i]);
        }
      }  // for
      log_dis("}, %s", indexBuf);
      break;
    }
    case k3rc:     // op {vCCCC .. v(CCCC+AA-1)}, thing@BBBB
    case k4rcc: {  // op {vCCCC .. v(CCCC+AA-1)}, method@BBBB, proto@HHHH
                   // NOT SUPPORTED:
      // case k3rms:       // [opt] invoke-virtual+super/range
      // case k3rmi:       // [opt] execute-inline/range
      // This doesn't match the "dx" output when some of the args are
      // 64-bit values -- dx only shows the first register.
      log_dis(" {");
      for (int i = 0, n = dexInstr_getVRegA(codePtr); i < n; i++) {
        if (i == 0) {
          log_dis("v%d", dexInstr_getVRegC(codePtr) + i);
        } else {
          log_dis(", v%d", dexInstr_getVRegC(codePtr) + i);
        }
      }  // for
      log_dis("}, %s", indexBuf);
    } break;
    case k51l: {  // op vAA, #+BBBBBBBBBBBBBBBB
      // This is often, but not always, a double.
      union {
        double d;
        u8 j;
      } conv;
      conv.j = dexInstr_getWideVRegB(codePtr);
      log_dis(" v%d, #double %g // #%016" PRIx64, dexInstr_getVRegA(codePtr), conv.d,
              dexInstr_getWideVRegB(codePtr));
      break;
    }
    // NOT SUPPORTED:
    // case k00x:        // unknown op or breakpoint
    //    break;
    default:
      log_dis(" ???");
      break;
  }  // switch

  log_dis("\n");
  free((void *)indexBuf);
}

char *dex_descriptorToDot(const char *str) {
  int targetLen = strlen(str);
  int offset = 0;

  // Strip leading [s; will be added to end.
  while (targetLen > 1 && str[offset] == '[') {
    offset++;
    targetLen--;
  }  // while

  const int arrayDepth = offset;

  if (targetLen == 1) {
    // Primitive type.
    str = primitiveTypeLabel(str[offset]);
    offset = 0;
    targetLen = strlen(str);
  } else {
    // Account for leading 'L' and trailing ';'.
    if (targetLen >= 2 && str[offset] == 'L' && str[offset + targetLen - 1] == ';') {
      targetLen -= 2;
      offset++;
    }
  }

  // Copy class name over.
  char *newStr = utils_calloc(targetLen + arrayDepth * 2 + 1);
  int i = 0;
  for (; i < targetLen; i++) {
    const char ch = str[offset + i];
    newStr[i] = (ch == '/' || ch == '$') ? '.' : ch;
  }  // for

  // Add the appropriate number of brackets for arrays.
  for (int j = 0; j < arrayDepth; j++) {
    newStr[i++] = '[';
    newStr[i++] = ']';
  }  // for

  newStr[i] = '\0';
  return newStr;
}

char *dex_descriptorClassToDot(const char *str) {
  // Reduce to just the class name prefix.
  const char *lastSlash = strrchr(str, '/');
  if (lastSlash == NULL) {
    lastSlash = str + 1;  // start past 'L'
  } else {
    lastSlash++;  // start past '/'
  }

  // Copy class name over, trimming trailing ';'.
  size_t targetLen = strlen(lastSlash);
  char *newStr = utils_calloc(targetLen);
  for (size_t i = 0; i < targetLen - 1; i++) {
    const char ch = lastSlash[i];
    newStr[i] = ch == '$' ? '.' : ch;
  }  // for
  newStr[targetLen - 1] = '\0';
  return newStr;
}

char *dex_descriptorClassToDotLong(const char *str) {
  size_t len = strlen(str);
  if (str[0] == 'L') {
    len -= 2;  // Two fewer chars to copy (trims L and ;).
    str++;     // Start past 'L'.
  }
  char *newStr = utils_calloc(len + 1);
  for (size_t i = 0; i < len; i++) {
    newStr[i] = (str[i] == '/') ? '.' : str[i];
  }
  newStr[len] = '\0';
  return newStr;
}

void dex_setDisassemblerStatus(bool status) { enableDisassembler = status; }
bool dex_getDisassemblerStatus(void) { return enableDisassembler; }

void dex_setClassRecover(bool status) { enableClassRecover = status; }
bool dex_getClassRecover(void) { return enableClassRecover; }
