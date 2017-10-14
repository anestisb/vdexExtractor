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

bool dex_isValidDexMagic(const dexHeader *pDexHeader) {
  /* Validate magic number */
  if (memcmp(pDexHeader->magic.dex, kDexMagic, sizeof(kDexMagic)) != 0) {
    return false;
  }

  /* Validate magic version */
  const char *version = pDexHeader->magic.ver;
  for (uint32_t i = 0; i < kNumDexVersions; i++) {
    if (memcmp(version, kDexMagicVersions[i], kDexVersionLen) == 0) {
      LOGMSG(l_DEBUG, "DEX version '%s' detected", pDexHeader->magic.ver);
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

uint32_t dex_computeDexCRC(const uint8_t *buf, off_t fileSz) {
  uint32_t adler_checksum = adler32(0L, Z_NULL, 0);
  const uint8_t non_sum = sizeof(dexMagic) + sizeof(uint32_t);
  const uint8_t *non_sum_ptr = buf + non_sum;
  adler_checksum = adler32(adler_checksum, non_sum_ptr, fileSz - non_sum);
  return adler_checksum;
}

void dex_repairDexCRC(const uint8_t *buf, off_t fileSz) {
  uint32_t adler_checksum = dex_computeDexCRC(buf, fileSz);
  memcpy((void *)buf + sizeof(dexMagic), &adler_checksum, sizeof(uint32_t));
}

uint32_t dex_readULeb128(const u1 **pStream) {
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
          /*
           * Note: We don't check to see if cur is out of
           * range here, meaning we tolerate garbage in the
           * high four-order bits.
           */
          cur = *(ptr++);
          result |= cur << 28;
        }
      }
    }
  }

  *pStream = ptr;
  return (uint32_t)result;
}

int32_t dex_readSLeb128(const uint8_t **data) {
  const uint8_t *ptr = *data;
  int32_t result = *(ptr++);
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

void dex_readClassDataHeader(const uint8_t **cursor, dexClassDataHeader *pDexClassDataHeader) {
  pDexClassDataHeader->staticFieldsSize = dex_readULeb128(cursor);
  pDexClassDataHeader->instanceFieldsSize = dex_readULeb128(cursor);
  pDexClassDataHeader->directMethodsSize = dex_readULeb128(cursor);
  pDexClassDataHeader->virtualMethodsSize = dex_readULeb128(cursor);
}

void dex_readClassDataField(const uint8_t **cursor, dexField *pDexField) {
  pDexField->fieldIdx = dex_readULeb128(cursor);
  pDexField->accessFlags = dex_readULeb128(cursor);
}

void dex_readClassDataMethod(const uint8_t **cursor, dexMethod *pDexMethod) {
  pDexMethod->methodIdx = dex_readULeb128(cursor);
  pDexMethod->accessFlags = dex_readULeb128(cursor);
  pDexMethod->codeOff = dex_readULeb128(cursor);
}

uint32_t dex_getFirstInstrOff(const dexMethod *pDexMethod) {
  // The first instruction is the last member of the dexCode struct
  return pDexMethod->codeOff + sizeof(dexCode) - sizeof(u2);
}
