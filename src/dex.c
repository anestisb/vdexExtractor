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

#include "dex.h"

#include "utils.h"

static bool enableDisassembler = false;

static inline u2 get2LE(unsigned char const *pSrc) { return pSrc[0] | (pSrc[1] << 8); }

static inline bool IsLeb128Terminator(const u1 *ptr) { return *ptr <= 0x7f; }

// Returns the number of bytes needed to encode the value in unsigned LEB128.
static inline u4 ULeb128Size(u4 data) {
  // bits_to_encode = (data != 0) ? 32 - CLZ(x) : 1  // 32 - CLZ(data | 1)
  // bytes = ceil(bits_to_encode / 7.0);             // (6 + bits_to_encode) / 7
  u4 x = 6 + 32 - __builtin_clz(data | 1U);

  // Division by 7 is done by (x * 37) >> 8 where 37 = ceil(256 / 7).
  // This works for 0 <= x < 256 / (7 * 37 - 256), i.e. 0 <= x <= 85.
  return (x * 37) >> 8;
}

static inline bool IsPowerOfTwo(u4 x) { return (x & (x - 1)) == 0; }

static inline bool IsFirstBitSet(u4 value) { return !IsPowerOfTwo(value & kAccVisibilityFlags); }

static inline u4 GetSecondFlag(u4 value) {
  return ((value & kAccNative) != 0) ? kAccDexHiddenBitNative : kAccDexHiddenBit;
}

// Helper for dex_dumpInstruction(), which builds the string representation
// for the index in the given instruction.
static char *indexString(const u1 *dexFileBuf, u2 *codePtr, u4 bufSize) {
  char *buf = utils_calloc(bufSize);
  static const u4 kInvalidIndex = USHRT_MAX;

  // Determine index and width of the string.
  u4 index = 0;
  u4 secondary_index = kInvalidIndex;
  u4 width = 4;
  switch (kInstructionDescriptors[dexInstr_getOpcode(codePtr)].format) {
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
  switch (kInstructionDescriptors[dexInstr_getOpcode(codePtr)].index_type) {
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
      if (index < dex_getTypeIdsSize(dexFileBuf)) {
        const char *tp = dex_getStringByTypeIdx(dexFileBuf, index);
        outSize = snprintf(buf, bufSize, "%s // type@%0*x", tp, width, index);
      } else {
        outSize = snprintf(buf, bufSize, "<type?> // type@%0*x", width, index);
      }
      break;
    case kIndexStringRef:
      if (index < dex_getStringIdsSize(dexFileBuf)) {
        const char *st = dex_getStringDataByIdx(dexFileBuf, index);
        outSize = snprintf(buf, bufSize, "\"%s\" // string@%0*x", st, width, index);
      } else {
        outSize = snprintf(buf, bufSize, "<string?> // string@%0*x", width, index);
      }
      break;
    case kIndexMethodRef:
      if (index < dex_getMethodIdsSize(dexFileBuf)) {
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
      if (index < dex_getFieldIdsSize(dexFileBuf)) {
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

      if (index < dex_getMethodIdsSize(dexFileBuf)) {
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
      if (secondary_index < dex_getProtoIdsSize(dexFileBuf)) {
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

// Return true if the code item has any preheaders.
static bool hasAnyPreHeader(u2 insnsCountAndFlags) {
  return (insnsCountAndFlags & kFlagPreHeaderCombined) != 0;
}

static bool hasPreHeader(u2 insnsCountAndFlags, u2 flag) {
  return (insnsCountAndFlags & flag) != 0;
}

dexType dex_checkType(const u1 *cursor) {
  if (memcmp(cursor, kDexMagic, sizeof(kDexMagic)) == 0) {
    return kNormalDex;
  }

  if (memcmp(cursor, kCDexMagic, sizeof(kCDexMagic)) == 0) {
    return kCompactDex;
  }

  return kDexInvalid;
}

bool dex_isValidDex(const u1 *cursor) {
  const dexHeader *pHeader = (dexHeader *)cursor;
  if (pHeader->headerSize != sizeof(dexHeader)) {
    return false;
  }

  // Validate magic number
  if (memcmp(pHeader->magic.dex, kDexMagic, sizeof(kDexMagic)) != 0) {
    return false;
  }

  // Validate magic version
  const char *version = pHeader->magic.ver;
  for (u4 i = 0; i < kNumDexVersions; i++) {
    if (memcmp(version, kDexMagicVersions[i], kDexVersionLen) == 0) {
      LOGMSG(l_DEBUG, "Dex version '%s' detected", pHeader->magic.ver);
      return true;
    }
  }
  return false;
}

bool dex_isValidCDex(const u1 *cursor) {
  const cdexHeader *pHeader = (cdexHeader *)cursor;
  if (pHeader->headerSize != sizeof(cdexHeader)) {
    LOGMSG(l_ERROR, "Invalid header size (%" PRIx32 " vs %" PRIx32 ")", pHeader->headerSize,
           sizeof(cdexHeader));
    return false;
  }

  // Validate magic number
  if (memcmp(pHeader->magic.dex, kCDexMagic, sizeof(kCDexMagic)) != 0) {
    return false;
  }

  // Validate magic version
  const char *version = pHeader->magic.ver;
  for (u4 i = 0; i < kNumCDexVersions; i++) {
    if (memcmp(version, kCDexMagicVersions[i], kDexVersionLen) == 0) {
      LOGMSG(l_DEBUG, "CompactDex version '%s' detected", pHeader->magic.ver);
      return true;
    }
  }
  return false;
}

dexMagic dex_getMagic(const u1 *cursor) {
  if (dex_checkType(cursor) == kNormalDex) {
    return ((const dexHeader *)cursor)->magic;
  } else {
    return ((const cdexHeader *)cursor)->magic;
  }
}

u4 dex_getChecksum(const u1 *cursor) {
  if (dex_checkType(cursor) == kNormalDex) {
    return ((const dexHeader *)cursor)->checksum;
  } else {
    return ((const cdexHeader *)cursor)->checksum;
  }
}

u4 dex_getFileSize(const u1 *cursor) {
  if (dex_checkType(cursor) == kNormalDex) {
    return ((const dexHeader *)cursor)->fileSize;
  } else {
    return ((const cdexHeader *)cursor)->fileSize;
  }
}

u4 dex_getHeaderSize(const u1 *cursor) {
  if (dex_checkType(cursor) == kNormalDex) {
    return ((const dexHeader *)cursor)->headerSize;
  } else {
    return ((const cdexHeader *)cursor)->headerSize;
  }
}

u4 dex_getEndianTag(const u1 *cursor) {
  if (dex_checkType(cursor) == kNormalDex) {
    return ((const dexHeader *)cursor)->endianTag;
  } else {
    return ((const cdexHeader *)cursor)->endianTag;
  }
}

u4 dex_getLinkSize(const u1 *cursor) {
  if (dex_checkType(cursor) == kNormalDex) {
    return ((const dexHeader *)cursor)->linkSize;
  } else {
    return ((const cdexHeader *)cursor)->linkSize;
  }
}

u4 dex_getLinkOff(const u1 *cursor) {
  if (dex_checkType(cursor) == kNormalDex) {
    return ((const dexHeader *)cursor)->linkOff;
  } else {
    return ((const cdexHeader *)cursor)->linkOff;
  }
}

u4 dex_getMapOff(const u1 *cursor) {
  if (dex_checkType(cursor) == kNormalDex) {
    return ((const dexHeader *)cursor)->mapOff;
  } else {
    return ((const cdexHeader *)cursor)->mapOff;
  }
}

u4 dex_getStringIdsSize(const u1 *cursor) {
  if (dex_checkType(cursor) == kNormalDex) {
    return ((const dexHeader *)cursor)->stringIdsSize;
  } else {
    return ((const cdexHeader *)cursor)->stringIdsSize;
  }
}

u4 dex_getStringIdsOff(const u1 *cursor) {
  if (dex_checkType(cursor) == kNormalDex) {
    return ((const dexHeader *)cursor)->stringIdsOff;
  } else {
    return ((const cdexHeader *)cursor)->stringIdsOff;
  }
}

u4 dex_getTypeIdsSize(const u1 *cursor) {
  if (dex_checkType(cursor) == kNormalDex) {
    return ((const dexHeader *)cursor)->typeIdsSize;
  } else {
    return ((const cdexHeader *)cursor)->typeIdsSize;
  }
}

u4 dex_getTypeIdsOff(const u1 *cursor) {
  if (dex_checkType(cursor) == kNormalDex) {
    return ((const dexHeader *)cursor)->typeIdsOff;
  } else {
    return ((const cdexHeader *)cursor)->typeIdsOff;
  }
}

u4 dex_getProtoIdsSize(const u1 *cursor) {
  if (dex_checkType(cursor) == kNormalDex) {
    return ((const dexHeader *)cursor)->protoIdsSize;
  } else {
    return ((const cdexHeader *)cursor)->protoIdsSize;
  }
}

u4 dex_getProtoIdsOff(const u1 *cursor) {
  if (dex_checkType(cursor) == kNormalDex) {
    return ((const dexHeader *)cursor)->protoIdsOff;
  } else {
    return ((const cdexHeader *)cursor)->protoIdsOff;
  }
}

u4 dex_getFieldIdsSize(const u1 *cursor) {
  if (dex_checkType(cursor) == kNormalDex) {
    return ((const dexHeader *)cursor)->fieldIdsSize;
  } else {
    return ((const cdexHeader *)cursor)->fieldIdsSize;
  }
}

u4 dex_getFieldIdsOff(const u1 *cursor) {
  if (dex_checkType(cursor) == kNormalDex) {
    return ((const dexHeader *)cursor)->fieldIdsOff;
  } else {
    return ((const cdexHeader *)cursor)->fieldIdsOff;
  }
}

u4 dex_getMethodIdsSize(const u1 *cursor) {
  if (dex_checkType(cursor) == kNormalDex) {
    return ((const dexHeader *)cursor)->methodIdsSize;
  } else {
    return ((const cdexHeader *)cursor)->methodIdsSize;
  }
}

u4 dex_getMethodIdsOff(const u1 *cursor) {
  if (dex_checkType(cursor) == kNormalDex) {
    return ((const dexHeader *)cursor)->methodIdsOff;
  } else {
    return ((const cdexHeader *)cursor)->methodIdsOff;
  }
}

u4 dex_getClassDefsSize(const u1 *cursor) {
  if (dex_checkType(cursor) == kNormalDex) {
    return ((const dexHeader *)cursor)->classDefsSize;
  } else {
    return ((const cdexHeader *)cursor)->classDefsSize;
  }
}

u4 dex_getClassDefsOff(const u1 *cursor) {
  if (dex_checkType(cursor) == kNormalDex) {
    return ((const dexHeader *)cursor)->classDefsOff;
  } else {
    return ((const cdexHeader *)cursor)->classDefsOff;
  }
}

u4 dex_getDataSize(const u1 *cursor) {
  if (dex_checkType(cursor) == kNormalDex) {
    return ((const dexHeader *)cursor)->dataSize;
  } else {
    return ((const cdexHeader *)cursor)->dataSize;
  }
}

u4 dex_getDataOff(const u1 *cursor) {
  if (dex_checkType(cursor) == kNormalDex) {
    return ((const dexHeader *)cursor)->dataOff;
  } else {
    return ((const cdexHeader *)cursor)->dataOff;
  }
}

u4 dex_getFeatureFlags(const u1 *cursor) {
  CHECK(dex_checkType(cursor) == kCompactDex);
  return ((const cdexHeader *)cursor)->featureFlags;
}

u4 dex_getDebugInfoOffsetsPos(const u1 *cursor) {
  CHECK(dex_checkType(cursor) == kCompactDex);
  return ((const cdexHeader *)cursor)->debugInfoOffsetsPos;
}

u4 dex_getDebugInfoOffsetsTableOffset(const u1 *cursor) {
  CHECK(dex_checkType(cursor) == kCompactDex);
  return ((const cdexHeader *)cursor)->debugInfoOffsetsTableOffset;
}

u4 dex_getDebugInfoBase(const u1 *cursor) {
  CHECK(dex_checkType(cursor) == kCompactDex);
  return ((const cdexHeader *)cursor)->debugInfoBase;
}

u4 dex_getOwnedDataBegin(const u1 *cursor) {
  CHECK(dex_checkType(cursor) == kCompactDex);
  return ((const cdexHeader *)cursor)->ownedDataBegin;
}

u4 dex_getOwnedDataEnd(const u1 *cursor) {
  CHECK(dex_checkType(cursor) == kCompactDex);
  return ((const cdexHeader *)cursor)->ownedDataEnd;
}

const u1 *dex_getDataAddr(const u1 *cursor) {
  if (dex_checkType(cursor) == kNormalDex) {
    return cursor;
  } else {
    return cursor + dex_getDataOff(cursor);
  }
}

void dex_dumpHeaderInfo(const u1 *cursor) {
  dexMagic magic = dex_getMagic(cursor);
  char *sigHex = utils_bin2hex(cursor + sizeof(dexMagic) + sizeof(u4), kSHA1Len);

  LOGMSG(l_DEBUG, "------ Dex Header Info ------");
  if (dex_checkType(cursor) == kNormalDex) {
    LOGMSG(l_DEBUG, "magic        : %.3s-%.3s", magic.dex, magic.ver);
  } else {
    LOGMSG(l_DEBUG, "magic        : %.4s-%.4s", magic.dex, magic.ver);
  }
  LOGMSG(l_DEBUG, "checksum     : %" PRIx32 " (%" PRIu32 ")", dex_getChecksum(cursor),
         dex_getChecksum(cursor));
  LOGMSG(l_DEBUG, "signature    : %s", sigHex);
  LOGMSG(l_DEBUG, "fileSize     : %" PRIx32 " (%" PRIu32 ")", dex_getFileSize(cursor),
         dex_getFileSize(cursor));
  LOGMSG(l_DEBUG, "headerSize   : %" PRIx32 " (%" PRIu32 ")", dex_getHeaderSize(cursor),
         dex_getHeaderSize(cursor));
  LOGMSG(l_DEBUG, "endianTag    : %" PRIx32 " (%" PRIu32 ")", dex_getEndianTag(cursor),
         dex_getEndianTag(cursor));
  LOGMSG(l_DEBUG, "linkSize     : %" PRIx32 " (%" PRIu32 ")", dex_getLinkSize(cursor),
         dex_getLinkSize(cursor));
  LOGMSG(l_DEBUG, "linkOff      : %" PRIx32 " (%" PRIu32 ")", dex_getLinkOff(cursor),
         dex_getLinkOff(cursor));
  LOGMSG(l_DEBUG, "mapOff       : %" PRIx32 " (%" PRIu32 ")", dex_getMapOff(cursor),
         dex_getMapOff(cursor));
  LOGMSG(l_DEBUG, "stringIdsSize: %" PRIx32 " (%" PRIu32 ")", dex_getStringIdsSize(cursor),
         dex_getStringIdsSize(cursor));
  LOGMSG(l_DEBUG, "stringIdsOff : %" PRIx32 " (%" PRIu32 ")", dex_getStringIdsOff(cursor),
         dex_getStringIdsOff(cursor));
  LOGMSG(l_DEBUG, "typeIdsSize  : %" PRIx32 " (%" PRIu32 ")", dex_getTypeIdsSize(cursor),
         dex_getTypeIdsSize(cursor));
  LOGMSG(l_DEBUG, "typeIdsOff   : %" PRIx32 " (%" PRIu32 ")", dex_getTypeIdsOff(cursor),
         dex_getTypeIdsOff(cursor));
  LOGMSG(l_DEBUG, "protoIdsSize : %" PRIx32 " (%" PRIu32 ")", dex_getProtoIdsSize(cursor),
         dex_getProtoIdsSize(cursor));
  LOGMSG(l_DEBUG, "protoIdsOff  : %" PRIx32 " (%" PRIu32 ")", dex_getProtoIdsOff(cursor),
         dex_getProtoIdsOff(cursor));
  LOGMSG(l_DEBUG, "fieldIdsSize : %" PRIx32 " (%" PRIu32 ")", dex_getFieldIdsSize(cursor),
         dex_getFieldIdsSize(cursor));
  LOGMSG(l_DEBUG, "fieldIdsOff  : %" PRIx32 " (%" PRIu32 ")", dex_getFieldIdsOff(cursor),
         dex_getFieldIdsOff(cursor));
  LOGMSG(l_DEBUG, "methodIdsSize: %" PRIx32 " (%" PRIu32 ")", dex_getMethodIdsSize(cursor),
         dex_getMethodIdsSize(cursor));
  LOGMSG(l_DEBUG, "methodIdsOff : %" PRIx32 " (%" PRIu32 ")", dex_getMethodIdsOff(cursor),
         dex_getMethodIdsOff(cursor));
  LOGMSG(l_DEBUG, "classDefsSize: %" PRIx32 " (%" PRIu32 ")", dex_getClassDefsSize(cursor),
         dex_getClassDefsSize(cursor));
  LOGMSG(l_DEBUG, "classDefsOff : %" PRIx32 " (%" PRIu32 ")", dex_getClassDefsOff(cursor),
         dex_getClassDefsOff(cursor));
  LOGMSG(l_DEBUG, "dataSize     : %" PRIx32 " (%" PRIu32 ")", dex_getDataSize(cursor),
         dex_getDataSize(cursor));
  LOGMSG(l_DEBUG, "dataOff      : %" PRIx32 " (%" PRIu32 ")", dex_getDataOff(cursor),
         dex_getDataOff(cursor));

  if (dex_checkType(cursor) == kCompactDex) {
    LOGMSG(l_DEBUG, "featureFlags                : %" PRIx32 " (%" PRIu32 ")",
           dex_getFeatureFlags(cursor), dex_getFeatureFlags(cursor));
    LOGMSG(l_DEBUG, "debuginfoOffsetsPos         : %" PRIx32 " (%" PRIu32 ")",
           dex_getDebugInfoOffsetsPos(cursor), dex_getDebugInfoOffsetsPos(cursor));
    LOGMSG(l_DEBUG, "debugInfoOffsetsTableOffset : %" PRIx32 " (%" PRIu32 ")",
           dex_getDebugInfoOffsetsTableOffset(cursor), dex_getDebugInfoOffsetsTableOffset(cursor));
    LOGMSG(l_DEBUG, "debugInfoBase               : %" PRIx32 " (%" PRIu32 ")",
           dex_getDebugInfoBase(cursor), dex_getDebugInfoBase(cursor));
    LOGMSG(l_DEBUG, "ownedDataBegin              : %" PRIx32 " (%" PRIu32 ")",
           dex_getOwnedDataBegin(cursor), dex_getOwnedDataBegin(cursor));
    LOGMSG(l_DEBUG, "ownedDataEnd                : %" PRIx32 " (%" PRIu32 ")",
           dex_getOwnedDataEnd(cursor), dex_getOwnedDataEnd(cursor));
  }

  LOGMSG(l_DEBUG, "-----------------------------");

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

u4 dex_getFirstInstrOff(const u1 *cursor, const dexMethod *pDexMethod) {
  // The first instruction is the last member of the dexCode struct
  if (dex_checkType(cursor) == kNormalDex) {
    return pDexMethod->codeOff + sizeof(dexCode) - sizeof(u2);
  } else {
    return pDexMethod->codeOff + sizeof(cdexCode) - sizeof(u2);
  }
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

u1 *dex_writeULeb128(u1 *dest, u4 value) {
  u1 out = value & 0x7f;
  value >>= 7;
  while (value != 0) {
    *dest++ = out | 0x80;
    out = value & 0x7f;
    value >>= 7;
  }
  *dest++ = out;
  return dest;
}

u1 *dex_reverseSearchULeb128(u1 *end_ptr) {
  u1 *ptr = end_ptr;

  // Move one byte back, check that this is the terminating byte.
  ptr--;
  CHECK(IsLeb128Terminator(ptr));

  // Keep moving back while the previous byte is not a terminating byte.
  // Fail after reading five bytes in case there isn't another Leb128 value
  // before this one.
  while (!IsLeb128Terminator(ptr - 1)) {
    ptr--;
    CHECK_LE(end_ptr - ptr, 5);
  }

  return ptr;
}

void dex_updateULeb128(u1 *dest, u4 value) {
  const u1 *old_end = dest;
  u4 old_value = dex_readULeb128(&old_end);
  CHECK_LE(ULeb128Size(value), ULeb128Size(old_value));
  for (u1 *end = dex_writeULeb128(dest, value); end < old_end; end++) {
    // Use longer encoding than necessary to fill the allocated space.
    end[-1] |= 0x80;
    end[0] = 0;
  }
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
  CHECK_LT(idx, dex_getStringIdsSize(dexFileBuf));
  dexStringId *dexStringIds = (dexStringId *)(dexFileBuf + dex_getStringIdsOff(dexFileBuf));
  return &dexStringIds[idx];
}

// Returns the dexTypeId at the specified index.
const dexTypeId *dex_getTypeId(const u1 *dexFileBuf, u2 idx) {
  CHECK_LT(idx, dex_getTypeIdsSize(dexFileBuf));
  dexTypeId *dexTypeIds = (dexTypeId *)(dexFileBuf + dex_getTypeIdsOff(dexFileBuf));
  return &dexTypeIds[idx];
}

// Returns the dexProtoId at the specified index.
const dexProtoId *dex_getProtoId(const u1 *dexFileBuf, u2 idx) {
  CHECK_LT(idx, dex_getProtoIdsSize(dexFileBuf));
  dexProtoId *dexProtoIds = (dexProtoId *)(dexFileBuf + dex_getProtoIdsOff(dexFileBuf));
  return &dexProtoIds[idx];
}

// Returns the dexFieldId at the specified index.
const dexFieldId *dex_getFieldId(const u1 *dexFileBuf, u4 idx) {
  CHECK_LT(idx, dex_getFieldIdsSize(dexFileBuf));
  dexFieldId *dexFieldIds = (dexFieldId *)(dexFileBuf + dex_getFieldIdsOff(dexFileBuf));
  return &dexFieldIds[idx];
}

// Returns the MethodId at the specified index.
const dexMethodId *dex_getMethodId(const u1 *dexFileBuf, u4 idx) {
  CHECK_LT(idx, dex_getMethodIdsSize(dexFileBuf));
  dexMethodId *dexMethodIds = (dexMethodId *)(dexFileBuf + dex_getMethodIdsOff(dexFileBuf));
  return &dexMethodIds[idx];
}

// Returns the ClassDef at the specified index.
const dexClassDef *dex_getClassDef(const u1 *dexFileBuf, u2 idx) {
  CHECK_LT(idx, dex_getClassDefsSize(dexFileBuf));
  dexClassDef *dexClassDefs = (dexClassDef *)(dexFileBuf + dex_getClassDefsOff(dexFileBuf));
  return &dexClassDefs[idx];
}

const char *dex_getStringDataAndUtf16Length(const u1 *dexFileBuf,
                                            const dexStringId *pDexStringId,
                                            u4 *utf16_length) {
  CHECK(utf16_length != NULL);
  const u1 *ptr = (u1 *)(dex_getDataAddr(dexFileBuf) + pDexStringId->stringDataOff);
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
    const u1 *addr = (u1 *)(dex_getDataAddr(dexFileBuf) + pDexProtoId->parametersOff);
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
  const char *srcFileName = "null";
  if (pDexClassDef->sourceFileIdx < USHRT_MAX) {
    srcFileName = dex_getStringDataByIdx(dexFileBuf, pDexClassDef->sourceFileIdx);
  }

  log_dis("  class #%" PRIu32 ": %s ('%s')\n", idx, classDescriptorFormated, classDescriptor);
  log_dis("   access=%04" PRIx32 " (%s)\n", pDexClassDef->accessFlags, classAccessStr);
  log_dis("   source_file=%s, class_data_off=%" PRIx32 " (%" PRIu32 ")\n", srcFileName,
          pDexClassDef->classDataOff, pDexClassDef->classDataOff);

  if (pDexClassDef->classDataOff != 0) {
    dexClassDataHeader pDexClassDataHeader;
    const u1 *curClassDataCursor = dex_getDataAddr(dexFileBuf) + pDexClassDef->classDataOff;
    memset(&pDexClassDataHeader, 0, sizeof(dexClassDataHeader));
    dex_readClassDataHeader(&curClassDataCursor, &pDexClassDataHeader);
    log_dis("   static_fields=%" PRIu32 ", instance_fields=%" PRIu32 ", direct_methods=%" PRIu32
            ", virtual_methods=%" PRIu32 "\n",
            pDexClassDataHeader.staticFieldsSize, pDexClassDataHeader.instanceFieldsSize,
            pDexClassDataHeader.directMethodsSize, pDexClassDataHeader.virtualMethodsSize);
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

void dex_dumpInstruction(
    const u1 *dexFileBuf, u2 *codePtr, u4 codeOffset, u4 insnIdx, bool highlight) {
  // Save time if no disassemble
  if (enableDisassembler == false) return;

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
  if (kInstructionDescriptors[dexInstr_getOpcode(codePtr)].index_type != kIndexNone) {
    const size_t kDefaultIndexStrLen = 256;
    indexBuf = indexString(dexFileBuf, codePtr, kDefaultIndexStrLen);
  }

  // Dump the instruction.
  switch (kInstructionDescriptors[dexInstr_getOpcode(codePtr)].format) {
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

void dex_DecodeCDexFields(cdexCode *pCdexCode,
                          u4 *insnsCount,
                          u2 *registersSize,
                          u2 *insSize,
                          u2 *outsSize,
                          u2 *triesSize,
                          bool decodeOnlyInsrCnt) {
  *insnsCount = pCdexCode->insnsCountAndFlags >> kInsnsSizeShift;
  if (!decodeOnlyInsrCnt) {
    const u2 fields = pCdexCode->fields;
    *registersSize = (fields >> kRegistersSizeShift) & 0xF;
    *insSize = (fields >> kInsSizeShift) & 0xF;
    *outsSize = (fields >> kOutsSizeShift) & 0xF;
    *triesSize = (fields >> kTriesSizeSizeShift) & 0xF;
  }

  if (hasAnyPreHeader(pCdexCode->insnsCountAndFlags)) {
    const u2 *preheader = (u2 *)(pCdexCode);
    if (hasPreHeader(pCdexCode->insnsCountAndFlags, kFlagPreHeaderInsnsSize)) {
      --preheader;
      *insnsCount += (u4)(*preheader);
      --preheader;
      *insnsCount += (u4)(*preheader) << 16;
    }
    if (!decodeOnlyInsrCnt) {
      if (hasPreHeader(pCdexCode->insnsCountAndFlags, kFlagPreHeaderRegisterSize)) {
        --preheader;
        *registersSize += preheader[0];
      }
      if (hasPreHeader(pCdexCode->insnsCountAndFlags, kFlagPreHeaderInsSize)) {
        --preheader;
        *insSize += preheader[0];
      }
      if (hasPreHeader(pCdexCode->insnsCountAndFlags, kFlagPreHeaderOutsSize)) {
        --preheader;
        *outsSize += preheader[0];
      }
      if (hasPreHeader(pCdexCode->insnsCountAndFlags, kFlagPreHeaderTriesSize)) {
        --preheader;
        *triesSize += preheader[0];
      }
    }
  }

  if (!decodeOnlyInsrCnt) {
    *registersSize += *insSize;
  }
}

void dex_getCodeItemInfo(const u1 *dexFileBuf, dexMethod *pDexMethod, u2 **pCode, u4 *codeSize) {
  // We have different code items in StandardDex and CompactDex
  if (dex_checkType(dexFileBuf) == kNormalDex) {
    dexCode *pDexCode = (dexCode *)(dex_getDataAddr(dexFileBuf) + pDexMethod->codeOff);
    *pCode = pDexCode->insns;
    *codeSize = pDexCode->insnsSize;
  } else {
    cdexCode *pCdexCode = (cdexCode *)(dex_getDataAddr(dexFileBuf) + pDexMethod->codeOff);
    *pCode = pCdexCode->insns;
    dex_DecodeCDexFields(pCdexCode, codeSize, NULL, NULL, NULL, NULL, true);
  }
}

u4 dex_decodeAccessFlagsFromDex(u4 dex_access_flags) {
  u4 new_access_flags = dex_access_flags;
  if (IsFirstBitSet(new_access_flags) != false) {
    new_access_flags ^= kAccVisibilityFlags;
  }
  new_access_flags &= ~GetSecondFlag(new_access_flags);
  return new_access_flags;
}

void dex_unhideAccessFlags(u1 *data_ptr, u4 new_access_flags, bool is_method) {
  // Go back 1 uleb to start.
  data_ptr = dex_reverseSearchULeb128(data_ptr);
  if (is_method) {
    // Methods have another uleb field before the access flags
    data_ptr = dex_reverseSearchULeb128(data_ptr);
  }
  dex_updateULeb128(data_ptr, new_access_flags);
}

void dex_setDisassemblerStatus(bool status) { enableDisassembler = status; }
bool dex_getDisassemblerStatus(void) { return enableDisassembler; }
