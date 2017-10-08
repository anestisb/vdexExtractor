#include "common.h"
#include "log.h"
#include "utils.h"
#include "vdex.h"

/*
 * Verify if valid VDEX file
 */
bool vdex_isMagicValid(const vdexHeader *pVdexHeader )
{
  return (memcmp(pVdexHeader->magic_, kVdexMagic, sizeof(kVdexMagic)) == 0);
}

bool vdex_isVersionValid(const vdexHeader *pVdexHeader )
{
  return (memcmp(pVdexHeader->version_, kVdexVersion, sizeof(kVdexVersion)) == 0);
}

bool vdex_isValidVDex(const vdexHeader *pVdexHeader)
{
  return vdex_isMagicValid(pVdexHeader) && vdex_isVersionValid(pVdexHeader);
}

bool vdex_hasDexSection(const uint8_t *buf)
{
  const vdexHeader *pVdexHeader = (const vdexHeader*)buf;
  return pVdexHeader->dex_size_ != 0;
}

size_t vdex_GetSizeOfChecksumsSection(const uint8_t *buf)
{
  const vdexHeader *pVdexHeader = (const vdexHeader*)buf;
  return sizeof(VdexChecksum) * pVdexHeader->number_of_dex_files_;
}

const uint8_t* vdex_DexBegin(const uint8_t *buf)
{
  return buf + sizeof(vdexHeader) + vdex_GetSizeOfChecksumsSection(buf);
}

const uint8_t* vdex_DexEnd(const uint8_t *buf)
{
  const vdexHeader *pVdexHeader = (const vdexHeader*)buf;
  return vdex_DexBegin(buf) + pVdexHeader->dex_size_;
}

const uint8_t* vdex_GetNextDexFileData(const uint8_t *buf, size_t *offset)
{
  if (*offset == 0) {
    if (vdex_hasDexSection(buf)) {
      const uint8_t *cursor = vdex_DexBegin(buf);
      *offset = sizeof(vdexHeader) + vdex_GetSizeOfChecksumsSection(buf);
      LOGMSG(l_DEBUG, "Processing first DEX file at offset:0x%x", *offset);

      // Adjust offset to point at the end of current DEX file
      dexHeader *pDexHeader = (dexHeader*)(cursor);
      *offset += pDexHeader->fileSize;
      return cursor;
    } else {
      return NULL;
    }
  } else {
    dexHeader *pDexHeader = (dexHeader*)(buf + *offset);

    // Check boundaries
    const uint8_t *cursor = buf + *offset;
    const uint8_t *cursorMax = cursor + pDexHeader->fileSize;
    if (cursorMax == vdex_DexEnd(buf)) {
      LOGMSG(l_DEBUG, "Processing last DEX file at offset:0x%x", *offset);
    } else if (cursorMax <= vdex_DexEnd(buf)) {
      LOGMSG(l_DEBUG, "Processing DEX file at offset:0x%x", *offset);
    } else {
      LOGMSG(l_ERROR, "Invalid cursor offset '0x%x'", *offset);
      return NULL;
    }

    // Adjust offset to point at the end of current DEX file
    *offset += pDexHeader->fileSize;
    return cursor;
  }
}

uint32_t vdex_GetLocationChecksum(const uint8_t *buf, uint32_t fileIdx)
{
  return (buf + sizeof(vdexHeader))[fileIdx];
}

const uint8_t* vdex_GetVerifierDepsData(const uint8_t *buf)
{
  const vdexHeader *pVdexHeader = (const vdexHeader*)buf;
  return buf + pVdexHeader->dex_size_;
}

uint32_t vdex_GetVerifierDepsDataSize(const uint8_t *buf)
{
  const vdexHeader *pVdexHeader = (const vdexHeader*)buf;
  return pVdexHeader->verifier_deps_size_;
}

const uint8_t* vdex_GetQuickeningInfo(const uint8_t *buf)
{
  const vdexHeader *pVdexHeader = (const vdexHeader*)buf;
  return buf + pVdexHeader->dex_size_ + pVdexHeader->verifier_deps_size_;
}

uint32_t vdex_GetQuickeningInfoSize(const uint8_t *buf)
{
  const vdexHeader *pVdexHeader = (const vdexHeader*)buf;
  return pVdexHeader->quickening_info_size_;
}
