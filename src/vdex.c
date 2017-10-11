#include "common.h"
#include "log.h"
#include "utils.h"
#include "vdex.h"

/*
 * Verify if valid VDEX file
 */
bool vdex_isMagicValid(const uint8_t *cursor)
{
  const vdexHeader *pVdexHeader = (const vdexHeader*)cursor;
  return (memcmp(pVdexHeader->magic_, kVdexMagic, sizeof(kVdexMagic)) == 0);
}

bool vdex_isVersionValid(const uint8_t *cursor)
{
  const vdexHeader *pVdexHeader = (const vdexHeader*)cursor;
  return (memcmp(pVdexHeader->version_, kVdexVersion, sizeof(kVdexVersion)) == 0);
}

bool vdex_isValidVdex(const uint8_t *cursor)
{
  return vdex_isMagicValid(cursor) && vdex_isVersionValid(cursor);
}

bool vdex_hasDexSection(const uint8_t *cursor)
{
  const vdexHeader *pVdexHeader = (const vdexHeader*)cursor;
  return pVdexHeader->dex_size_ != 0;
}

size_t vdex_GetSizeOfChecksumsSection(const uint8_t *cursor)
{
  const vdexHeader *pVdexHeader = (const vdexHeader*)cursor;
  return sizeof(VdexChecksum) * pVdexHeader->number_of_dex_files_;
}

const uint8_t* vdex_DexBegin(const uint8_t *cursor)
{
  return cursor + sizeof(vdexHeader) + vdex_GetSizeOfChecksumsSection(cursor);
}

const uint8_t* vdex_DexEnd(const uint8_t *cursor)
{
  const vdexHeader *pVdexHeader = (const vdexHeader*)cursor;
  return vdex_DexBegin(cursor) + pVdexHeader->dex_size_;
}

const uint8_t* vdex_GetNextDexFileData(const uint8_t *cursor, size_t *offset)
{
  if (*offset == 0) {
    if (vdex_hasDexSection(cursor)) {
      const uint8_t *dexBuf = vdex_DexBegin(cursor);
      *offset = sizeof(vdexHeader) + vdex_GetSizeOfChecksumsSection(cursor);
      LOGMSG(l_DEBUG, "Processing first DEX file at offset:0x%x", *offset);

      // Adjust offset to point at the end of current DEX file
      dexHeader *pDexHeader = (dexHeader*)(dexBuf);
      *offset += pDexHeader->fileSize;
      return dexBuf;
    } else {
      return NULL;
    }
  } else {
    dexHeader *pDexHeader = (dexHeader*)(cursor + *offset);

    // Check boundaries
    const uint8_t *dexBuf = cursor + *offset;
    const uint8_t *dexBufMax = dexBuf + pDexHeader->fileSize;
    if (dexBufMax == vdex_DexEnd(cursor)) {
      LOGMSG(l_DEBUG, "Processing last DEX file at offset:0x%x", *offset);
    } else if (dexBufMax <= vdex_DexEnd(cursor)) {
      LOGMSG(l_DEBUG, "Processing DEX file at offset:0x%x", *offset);
    } else {
      LOGMSG(l_ERROR, "Invalid cursor offset '0x%x'", *offset);
      return NULL;
    }

    // Adjust offset to point at the end of current DEX file
    *offset += pDexHeader->fileSize;
    return dexBuf;
  }
}

uint32_t vdex_GetLocationChecksum(const uint8_t *cursor, uint32_t fileIdx)
{
  return (cursor + sizeof(vdexHeader))[fileIdx];
}

const uint8_t* vdex_GetVerifierDepsData(const uint8_t *cursor)
{
  const vdexHeader *pVdexHeader = (const vdexHeader*)cursor;
  return cursor + pVdexHeader->dex_size_;
}

uint32_t vdex_GetVerifierDepsDataSize(const uint8_t *cursor)
{
  const vdexHeader *pVdexHeader = (const vdexHeader*)cursor;
  return pVdexHeader->verifier_deps_size_;
}

const uint8_t* vdex_GetQuickeningInfo(const uint8_t *cursor)
{
  const vdexHeader *pVdexHeader = (const vdexHeader*)cursor;
  return cursor + pVdexHeader->dex_size_ + pVdexHeader->verifier_deps_size_;
}

uint32_t vdex_GetQuickeningInfoSize(const uint8_t *cursor)
{
  const vdexHeader *pVdexHeader = (const vdexHeader*)cursor;
  return pVdexHeader->quickening_info_size_;
}

bool vdex_Unquicken(const uint8_t *cursor)
{
  if (vdex_GetQuickeningInfoSize(cursor) == 0) {
    // If there is no quickening info, we bail early, as the code below expects at
    // least the size of quickening data for each method that has a code item.
    return true;
  }

  const vdexHeader *pVdexHeader = (const vdexHeader*)cursor;
  const uint8_t* quickening_info_ptr = vdex_GetQuickeningInfo(cursor);
  const uint8_t* const quickening_info_end = vdex_GetQuickeningInfo(cursor) +
    vdex_GetQuickeningInfoSize(cursor);

  const uint8_t *dexFileBuf = NULL;
  size_t offset = 0;

  // For each dex file
  for (size_t dex_file_idx = 0;
       dex_file_idx < pVdexHeader->number_of_dex_files_;
       ++dex_file_idx) {
    dexFileBuf = vdex_GetNextDexFileData(cursor, &offset);
    if (dexFileBuf == NULL) {
      LOGMSG(l_ERROR, "Failed to unquicken 'classes%zu.dex' - skipping",
             dex_file_idx);
      continue;
    }

    const dexHeader *pDexHeader = (const dexHeader*)dexFileBuf;

    // Check if valid dex file
    dex_dumpHeaderInfo(pDexHeader);
    if (!dex_isValidDexMagic(pDexHeader)) {
      LOGMSG(l_ERROR, "Failed to unquicken 'classes%zu.dex' - skipping",
             dex_file_idx);
      continue;
    }

    // For each class
    LOGMSG(l_DEBUG, "[%zu] number of classes: %zu", dex_file_idx, pDexHeader->classDefsSize);
    dexClassDef *dexClassDefs = (dexClassDef*)(dexFileBuf + pDexHeader->classDefsOff);

    utils_hexDump("dexClassDefs", (uint8_t*)dexClassDefs, 16);

    for (uint32_t i = 0; i < pDexHeader->classDefsSize; ++i) {
      LOGMSG(l_DEBUG, "[%zu] class #%zu: class_data_off=%zu", dex_file_idx, i,
             dexClassDefs[i].classDataOff);

      const dexClassData *pClassData;
      if (dexClassDefs[i].classDataOff == 0) {
        continue;
      } else {
        pClassData = (dexClassData*)(dexFileBuf + dexClassDefs[i].classDataOff);
      }

      LOGMSG(l_DEBUG, "[%zu] class #%zu: direct methods=%zu",
             dex_file_idx, i, pClassData->header.directMethodsSize);

      // For each direct method
      const dexMethod *dexDirectMethods = pClassData->directMethods;
      for (uint32_t j = 0; j < pClassData->header.directMethodsSize; ++j) {

        // Skip empty methods
        if (dexDirectMethods[j].codeOff == 0) {
          continue;
        }

        // Get method code offset and revert quickened instructions
        dexCode *pDexCode = (dexCode*)(dexFileBuf + dexDirectMethods[j].codeOff);

        // For quickening info blob the first 4bytes are the inner blobs size
        uint32_t quickening_size = *quickening_info_ptr;
        quickening_info_ptr += sizeof(uint32_t);
        if (!dex_DexcompileDriver(pDexCode,
                                  quickening_info_ptr,
                                  quickening_size, true)) {
          LOGMSG(l_ERROR, "Failed to decompile DEX file");
          return false;
        }
        quickening_info_ptr += quickening_size;
      }

      // For each virtual method
      const dexMethod *dexVirtualMethods = pClassData->virtualMethods;
      for (uint32_t j = 0; j < pClassData->header.virtualMethodsSize; ++j) {

        // Skip empty methods
        if (dexVirtualMethods[j].codeOff == 0) {
          continue;
        }

        // Get method code offset and revert quickened instructions
        dexCode *pDexCode = (dexCode*)(dexFileBuf + dexVirtualMethods[j].codeOff);

        // For quickening info blob the first 4bytes are the inner blobs size
        uint32_t quickening_size = *quickening_info_ptr;
        quickening_info_ptr += sizeof(uint32_t);
        if (!dex_DexcompileDriver(pDexCode,
                                  quickening_info_ptr,
                                  quickening_size, true)) {
          LOGMSG(l_ERROR, "Failed to decompile DEX file");
          return false;
        }
        quickening_info_ptr += quickening_size;
      }
    }
  }

  if (quickening_info_ptr != quickening_info_end) {
    LOGMSG(l_ERROR, "Failed to process all outer quickening info");
    return false;
  }

  return true;
}
