#include "common.h"
#include "log.h"
#include "utils.h"
#include "dex.h"

static uint8_t *quickening_info_ptr;
static uint8_t *quickening_info_end;

static uint16_t *code_ptr;
static uint16_t *code_end;
static uint32_t dex_pc;

static void initCodeIterator(uint16_t *pCode, uint32_t codeSize)
{
  code_ptr = pCode;
  code_end = pCode + codeSize;
  dex_pc = 0;
}

/* Under development */
#if 0
static bool isCodeIteratorDone()
{
  return code_ptr >= code_end;
}

static void codeIteratorAdvance()
{
  size_t instruction_size = *Instruction::At(code_ptr_).SizeInCodeUnits();
  code_ptr_ += instruction_size;
  dex_pc_ += instruction_size;
}
#endif

bool dex_isValidDexMagic(const dexHeader *pDexHeader)
{
    /* Validate DEX magic number */
    if (((memcmp(pDexHeader->magic.dex,  DEX_MAGIC, 3) != 0)    && // Check if DEX
         (memcmp(pDexHeader->magic.dex, ODEX_MAGIC, 3) != 0))   || // Check if ODEX
        (memcmp(pDexHeader->magic.nl,   "\n",      1) != 0)     || // Check for newline
        ((memcmp(pDexHeader->magic.ver, API_LE_13, 3) != 0) &&     // Check for API SDK <= 13
         (memcmp(pDexHeader->magic.ver, API_GE_14, 3) != 0) &&     // Check for API SDK >= 14
         (memcmp(pDexHeader->magic.ver, API_GE_22, 3) != 0))    || // Check for API SDK >= 22
        (memcmp(pDexHeader->magic.zero, "\0",      1) != 0)) {     // Check for zero

        return false;
    }
    else return true;
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
                          uint8_t *quickening_data_start,
                          uint32_t quickening_data_size,
                          bool decompile_return_instruction)
{
  if (quickening_data_size == 0 && !decompile_return_instruction) {
    return true;
  }

  quickening_info_ptr = quickening_data_start;
  quickening_info_end = quickening_data_start + quickening_data_size;
  initCodeIterator(pDexCode->insns, pDexCode->insns_size);

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
