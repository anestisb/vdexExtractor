#include "common.h"
#include "log.h"
#include "utils.h"
#include "dex.h"
#include "dex_instruction.h"

static const uint8_t *quickening_info_ptr;
static const uint8_t *quickening_info_end;

static uint16_t *code_ptr;
static uint16_t *code_end;
static uint32_t dex_pc;

static void initCodeIterator(uint16_t *pCode, uint32_t codeSize)
{
  code_ptr = pCode;
  code_end = pCode + codeSize;
  dex_pc = 0;
}

static bool isCodeIteratorDone()
{
  return code_ptr >= code_end;
}

static void codeIteratorAdvance()
{
  uint32_t instruction_size = dexInstr_SizeInCodeUnits(code_ptr);
  code_ptr += instruction_size;
  dex_pc += instruction_size;
}

bool dex_isValidDexMagic(const dexHeader *pDexHeader)
{
  /* Validate DEX magic number */
  if (((memcmp(pDexHeader->magic.dex,  DEX_MAGIC, 3) != 0)    && // Check if DEX
       (memcmp(pDexHeader->magic.dex, ODEX_MAGIC, 3) != 0))   || // Check if ODEX
      (memcmp(pDexHeader->magic.nl,   "\n",      1) != 0)     || // Check for newline
      ((memcmp(pDexHeader->magic.ver, API_LE_13, 3) != 0) &&     // Check for API <= 13
       (memcmp(pDexHeader->magic.ver, API_GE_14, 3) != 0) &&     // Check for API >= 14
       (memcmp(pDexHeader->magic.ver, API_GE_22, 3) != 0) &&     // Check for API >= 22
       (memcmp(pDexHeader->magic.ver, API_26,    3) != 0) &&     // Check for API == 26
       (memcmp(pDexHeader->magic.ver, API_GT_26, 3) != 0))    || // Check for API > 26
      (memcmp(pDexHeader->magic.zero, "\0",      1) != 0)) {     // Check for zero

      return false;
  } else {
    return true;
  }
}

void dex_dumpHeaderInfo(const dexHeader *pDexHeader)
{
  char *sigHex = util_bin2hex(pDexHeader->signature, SHA1Len);

  LOGMSG(l_DEBUG, "------ Dex Header Info ------");
  LOGMSG(l_DEBUG, "\tmagic        : %.3s-%.3s", pDexHeader->magic.dex,
         pDexHeader->magic.ver);
  LOGMSG(l_DEBUG, "\tchecksum     : %"PRIx32" (%"PRIu32")",
         pDexHeader->checksum, pDexHeader->checksum);
  LOGMSG(l_DEBUG, "\tsignature    : %s", sigHex);
  LOGMSG(l_DEBUG, "\tfileSize     : %"PRIx32" (%"PRIu32")",
         pDexHeader->fileSize, pDexHeader->fileSize);
  LOGMSG(l_DEBUG, "\theaderSize   : %"PRIx32" (%"PRIu32")",
         pDexHeader->headerSize, pDexHeader->headerSize);
  LOGMSG(l_DEBUG, "\tendianTag    : %"PRIx32" (%"PRIu32")",
         pDexHeader->endianTag, pDexHeader->endianTag);
  LOGMSG(l_DEBUG, "\tlinkSize     : %"PRIx32" (%"PRIu32")",
         pDexHeader->linkSize, pDexHeader->linkSize);
  LOGMSG(l_DEBUG, "\tlinkOff      : %"PRIx32" (%"PRIu32")",
         pDexHeader->linkOff, pDexHeader->linkOff);
  LOGMSG(l_DEBUG, "\tmapOff       : %"PRIx32" (%"PRIu32")",
         pDexHeader->mapOff, pDexHeader->mapOff);
  LOGMSG(l_DEBUG, "\tstringIdsSize: %"PRIx32" (%"PRIu32")",
         pDexHeader->stringIdsSize, pDexHeader->stringIdsSize);
  LOGMSG(l_DEBUG, "\tstringIdsOff : %"PRIx32" (%"PRIu32")",
         pDexHeader->stringIdsOff, pDexHeader->stringIdsOff);
  LOGMSG(l_DEBUG, "\ttypeIdsSize  : %"PRIx32" (%"PRIu32")",
         pDexHeader->typeIdsSize, pDexHeader->typeIdsSize);
  LOGMSG(l_DEBUG, "\ttypeIdsOff   : %"PRIx32" (%"PRIu32")",
         pDexHeader->typeIdsOff, pDexHeader->typeIdsOff);
  LOGMSG(l_DEBUG, "\tprotoIdsSize : %"PRIx32" (%"PRIu32")",
         pDexHeader->protoIdsSize, pDexHeader->protoIdsSize);
  LOGMSG(l_DEBUG, "\tprotoIdsOff  : %"PRIx32" (%"PRIu32")",
         pDexHeader->protoIdsOff, pDexHeader->protoIdsOff);
  LOGMSG(l_DEBUG, "\tfieldIdsSize : %"PRIx32" (%"PRIu32")",
         pDexHeader->fieldIdsSize, pDexHeader->fieldIdsSize);
  LOGMSG(l_DEBUG, "\tfieldIdsOff  : %"PRIx32" (%"PRIu32")",
         pDexHeader->fieldIdsOff, pDexHeader->fieldIdsOff);
  LOGMSG(l_DEBUG, "\tmethodIdsSize: %"PRIx32" (%"PRIu32")",
         pDexHeader->methodIdsSize, pDexHeader->methodIdsSize);
  LOGMSG(l_DEBUG, "\tmethodIdsOff : %"PRIx32" (%"PRIu32")",
         pDexHeader->methodIdsOff, pDexHeader->methodIdsOff);
  LOGMSG(l_DEBUG, "\tclassDefsSize: %"PRIx32" (%"PRIu32")",
         pDexHeader->classDefsSize, pDexHeader->classDefsSize);
  LOGMSG(l_DEBUG, "\tclassDefsOff : %"PRIx32" (%"PRIu32")",
         pDexHeader->classDefsOff, pDexHeader->classDefsOff);
  LOGMSG(l_DEBUG, "\tdataSize     : %"PRIx32" (%"PRIu32")",
         pDexHeader->dataSize, pDexHeader->dataSize);
  LOGMSG(l_DEBUG, "\tdataOff      : %"PRIx32" (%"PRIu32")", pDexHeader->dataOff,
         pDexHeader->dataOff);
  LOGMSG(l_DEBUG, "-----------------------------");

  free(sigHex);
}

void dex_repairDexCRC(const uint8_t *buf, off_t fileSz)
{
    /* Repair DEX CRC */
    uint32_t adler_checksum = adler32(0L, Z_NULL, 0);
    const uint8_t non_sum = sizeof(dexMagic) + sizeof(uint32_t);
    const uint8_t *non_sum_ptr = buf + non_sum;
    adler_checksum = adler32(adler_checksum, non_sum_ptr, fileSz - non_sum);
    memcpy((void*)buf + sizeof(dexMagic), &adler_checksum, sizeof(uint32_t));
}

bool dex_DexcompileDriver(dexCode *pDexCode,
                          const uint8_t *quickening_data_start,
                          uint32_t quickening_data_size,
                          bool decompile_return_instruction)
{
  if (quickening_data_size == 0 && !decompile_return_instruction) {
    return true;
  }

  quickening_info_ptr = quickening_data_start;
  quickening_info_end = quickening_data_start + quickening_data_size;
  initCodeIterator(pDexCode->insns, pDexCode->insns_size);

  while (isCodeIteratorDone() == false) {

    switch(dexInstr_getOpcode(code_ptr)) {
      case RETURN_VOID_NO_BARRIER:
        LOGMSG(l_INFO, "RETURN_VOID_NO_BARRIER");
      case NOP:
        LOGMSG(l_INFO, "NOP");
      case IGET_QUICK:
        LOGMSG(l_INFO, "IGET_QUICK");
      case IGET_WIDE_QUICK:
        LOGMSG(l_INFO, "IGET_WIDE_QUICK");
      case IGET_OBJECT_QUICK:
        LOGMSG(l_INFO, "IGET_OBJECT_QUICK");
      case IGET_BOOLEAN_QUICK:
        LOGMSG(l_INFO, "IGET_BOOLEAN_QUICK");
      case IGET_BYTE_QUICK:
        LOGMSG(l_INFO, "IGET_BYTE_QUICK");
      case IGET_CHAR_QUICK:
        LOGMSG(l_INFO, "IGET_CHAR_QUICK");
      case IGET_SHORT_QUICK:
        LOGMSG(l_INFO, "IGET_SHORT_QUICK");
      case IPUT_QUICK:
        LOGMSG(l_INFO, "IPUT_QUICK");
      case IPUT_BOOLEAN_QUICK:
        LOGMSG(l_INFO, "IPUT_BOOLEAN_QUICK");
      case IPUT_BYTE_QUICK:
        LOGMSG(l_INFO, "IPUT_BYTE_QUICK");
      case IPUT_CHAR_QUICK:
        LOGMSG(l_INFO, "IPUT_CHAR_QUICK");
      case IPUT_SHORT_QUICK:
        LOGMSG(l_INFO, "IPUT_SHORT_QUICK");
      case IPUT_WIDE_QUICK:
        LOGMSG(l_INFO, "IPUT_WIDE_QUICK");
      case IPUT_OBJECT_QUICK:
        LOGMSG(l_INFO, "IPUT_OBJECT_QUICK");
      case INVOKE_VIRTUAL_QUICK:
        LOGMSG(l_INFO, "INVOKE_VIRTUAL_QUICK");
      case INVOKE_VIRTUAL_RANGE_QUICK:
        LOGMSG(l_INFO, "INVOKE_VIRTUAL_RANGE_QUICK");
      default:
        break;
    }

    codeIteratorAdvance();
  }

  if (quickening_info_ptr != quickening_info_end) {
    if (quickening_data_start == quickening_info_ptr) {
      LOGMSG(l_ERROR, "Failed to use any value in quickening info, potentially due to duplicate methods.");
    } else {
      LOGMSG(l_ERROR, "Failed to use all values in quickening info.");
      return false;
    }
  }

  return true;
}

uint32_t dex_readULeb128(const u1** pStream)
{
    const u1* ptr = *pStream;
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

int32_t dex_readSLeb128(const uint8_t** data)
{
  const uint8_t* ptr = *data;
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

void dex_readClassDataHeader(const uint8_t *cursor,
                             dexClassDataHeader *pDexClassDataHeader)
{
  const uint8_t *ptr_pos = cursor;
  pDexClassDataHeader->staticFieldsSize = dex_readULeb128(&ptr_pos);
  pDexClassDataHeader->instanceFieldsSize = dex_readULeb128(&ptr_pos);
  pDexClassDataHeader->directMethodsSize = dex_readULeb128(&ptr_pos);
  pDexClassDataHeader->virtualMethodsSize = dex_readULeb128(&ptr_pos);
}

void dex_readClassDataField(const uint8_t *cursor, dexField *pDexField)
{
  const uint8_t *ptr_pos = cursor;
  pDexField->fieldIdx = dex_readULeb128(&ptr_pos);
  pDexField->accessFlags = dex_readULeb128(&ptr_pos);
}

void dex_readClassDataMethod(const uint8_t *cursor, dexMethod *pDexMethod)
{
  const uint8_t *ptr_pos = cursor;
  pDexMethod->methodIdx = dex_readULeb128(&ptr_pos);
  pDexMethod->accessFlags = dex_readULeb128(&ptr_pos);
  pDexMethod->codeOff = dex_readULeb128(&ptr_pos);
}
