#include "dex.h"
#include "log.h"
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

  LOGMSG(l_DEBUG, "------ Dex Header Info ------");
  LOGMSG(l_DEBUG, "\tmagic        : %.3s-%.3s", pDexHeader->magic.dex,
         pDexHeader->magic.ver);
  LOGMSG(l_DEBUG, "\tchecksum     : %" PRIx32 " (%" PRIu32 ")",
         pDexHeader->checksum, pDexHeader->checksum);
  LOGMSG(l_DEBUG, "\tsignature    : %s", sigHex);
  LOGMSG(l_DEBUG, "\tfileSize     : %" PRIx32 " (%" PRIu32 ")",
         pDexHeader->fileSize, pDexHeader->fileSize);
  LOGMSG(l_DEBUG, "\theaderSize   : %" PRIx32 " (%" PRIu32 ")",
         pDexHeader->headerSize, pDexHeader->headerSize);
  LOGMSG(l_DEBUG, "\tendianTag    : %" PRIx32 " (%" PRIu32 ")",
         pDexHeader->endianTag, pDexHeader->endianTag);
  LOGMSG(l_DEBUG, "\tlinkSize     : %" PRIx32 " (%" PRIu32 ")",
         pDexHeader->linkSize, pDexHeader->linkSize);
  LOGMSG(l_DEBUG, "\tlinkOff      : %" PRIx32 " (%" PRIu32 ")",
         pDexHeader->linkOff, pDexHeader->linkOff);
  LOGMSG(l_DEBUG, "\tmapOff       : %" PRIx32 " (%" PRIu32 ")",
         pDexHeader->mapOff, pDexHeader->mapOff);
  LOGMSG(l_DEBUG, "\tstringIdsSize: %" PRIx32 " (%" PRIu32 ")",
         pDexHeader->stringIdsSize, pDexHeader->stringIdsSize);
  LOGMSG(l_DEBUG, "\tstringIdsOff : %" PRIx32 " (%" PRIu32 ")",
         pDexHeader->stringIdsOff, pDexHeader->stringIdsOff);
  LOGMSG(l_DEBUG, "\ttypeIdsSize  : %" PRIx32 " (%" PRIu32 ")",
         pDexHeader->typeIdsSize, pDexHeader->typeIdsSize);
  LOGMSG(l_DEBUG, "\ttypeIdsOff   : %" PRIx32 " (%" PRIu32 ")",
         pDexHeader->typeIdsOff, pDexHeader->typeIdsOff);
  LOGMSG(l_DEBUG, "\tprotoIdsSize : %" PRIx32 " (%" PRIu32 ")",
         pDexHeader->protoIdsSize, pDexHeader->protoIdsSize);
  LOGMSG(l_DEBUG, "\tprotoIdsOff  : %" PRIx32 " (%" PRIu32 ")",
         pDexHeader->protoIdsOff, pDexHeader->protoIdsOff);
  LOGMSG(l_DEBUG, "\tfieldIdsSize : %" PRIx32 " (%" PRIu32 ")",
         pDexHeader->fieldIdsSize, pDexHeader->fieldIdsSize);
  LOGMSG(l_DEBUG, "\tfieldIdsOff  : %" PRIx32 " (%" PRIu32 ")",
         pDexHeader->fieldIdsOff, pDexHeader->fieldIdsOff);
  LOGMSG(l_DEBUG, "\tmethodIdsSize: %" PRIx32 " (%" PRIu32 ")",
         pDexHeader->methodIdsSize, pDexHeader->methodIdsSize);
  LOGMSG(l_DEBUG, "\tmethodIdsOff : %" PRIx32 " (%" PRIu32 ")",
         pDexHeader->methodIdsOff, pDexHeader->methodIdsOff);
  LOGMSG(l_DEBUG, "\tclassDefsSize: %" PRIx32 " (%" PRIu32 ")",
         pDexHeader->classDefsSize, pDexHeader->classDefsSize);
  LOGMSG(l_DEBUG, "\tclassDefsOff : %" PRIx32 " (%" PRIu32 ")",
         pDexHeader->classDefsOff, pDexHeader->classDefsOff);
  LOGMSG(l_DEBUG, "\tdataSize     : %" PRIx32 " (%" PRIu32 ")",
         pDexHeader->dataSize, pDexHeader->dataSize);
  LOGMSG(l_DEBUG, "\tdataOff      : %" PRIx32 " (%" PRIu32 ")",
         pDexHeader->dataOff, pDexHeader->dataOff);
  LOGMSG(l_DEBUG, "-----------------------------");

  free(sigHex);
}

void dex_repairDexCRC(const uint8_t *buf, off_t fileSz) {
  /* Repair DEX CRC */
  uint32_t adler_checksum = adler32(0L, Z_NULL, 0);
  const uint8_t non_sum = sizeof(dexMagic) + sizeof(uint32_t);
  const uint8_t *non_sum_ptr = buf + non_sum;
  adler_checksum = adler32(adler_checksum, non_sum_ptr, fileSz - non_sum);
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

void dex_readClassDataHeader(const uint8_t **cursor,
                             dexClassDataHeader *pDexClassDataHeader) {
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
