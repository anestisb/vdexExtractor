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

#ifndef _VDEX_H_
#define _VDEX_H_

#include <zlib.h>
#include "common.h"
#include "dex.h"

static const uint8_t kVdexMagic[] = { 'v', 'd', 'e', 'x' };
static const uint8_t kVdexVersion[] = { '0', '0', '6', '\0' };

typedef uint32_t VdexChecksum;

typedef struct __attribute__((packed)) {
  uint8_t magic_[4];
  uint8_t version_[4];
  uint32_t number_of_dex_files_;
  uint32_t dex_size_;
  uint32_t verifier_deps_size_;
  uint32_t quickening_info_size_;
} vdexHeader;

// Vdex files contain extracted Dex files.
// File format:
//   VdexFile::Header    fixed-length header
//
//   DEX[0]              array of the input DEX files
//   DEX[1]              the bytecode may have been quickened
//   ...
//   DEX[D]
//
typedef struct __attribute__((packed)) {
  vdexHeader *pVdexHeader;
  dexFile *pDexFiles;
} vdexFile;

// Verify if valid Vdex file
bool vdex_isValidVdex(const uint8_t *);
bool vdex_isMagicValid(const uint8_t *);
bool vdex_isVersionValid(const uint8_t *);

bool vdex_hasDexSection(const uint8_t *);
uint32_t vdex_GetSizeOfChecksumsSection(const uint8_t *);
const uint8_t *vdex_DexBegin(const uint8_t *);
const uint8_t *vdex_DexEnd(const uint8_t *);
const uint8_t *vdex_GetNextDexFileData(const uint8_t *, uint32_t *);
uint32_t vdex_GetLocationChecksum(const uint8_t *, uint32_t);
const uint8_t *vdex_GetVerifierDepsData(const uint8_t *);
uint32_t vdex_GetVerifierDepsDataSize(const uint8_t *);
const uint8_t *vdex_GetQuickeningInfo(const uint8_t *);
uint32_t vdex_GetQuickeningInfoSize(const uint8_t *);
bool vdex_Unquicken(const uint8_t *);

#endif
