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

#define kNumVdexVersions 1
#define kVdexVersionLen 4

static const u1 kVdexMagic[] = { 'v', 'd', 'e', 'x' };
static const u1 kVdexMagicVersions[kNumVdexVersions][kVdexVersionLen] = {
  // Vdex version 006: Android "O".
  { '0', '0', '6', '\0' },
  // Vdex verion 010: Beyond Android "O" (current dev-master).
  // { '0', '1', '0', '\0' },
};

typedef u4 VdexChecksum;

typedef struct __attribute__((packed)) {
  u1 magic_[4];
  u1 version_[4];
  u4 number_of_dex_files_;
  u4 dex_size_;
  u4 verifier_deps_size_;
  u4 quickening_info_size_;
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
  dexHeader *pDexFiles;
} vdexFile;

// Verify if valid Vdex file
bool vdex_isValidVdex(const u1 *);
bool vdex_isMagicValid(const u1 *);
bool vdex_isVersionValid(const u1 *);

bool vdex_hasDexSection(const u1 *);
u4 vdex_GetSizeOfChecksumsSection(const u1 *);
const u1 *vdex_DexBegin(const u1 *);
u4 vdex_DexBeginOffset(const u1 *);
const u1 *vdex_DexEnd(const u1 *);
u4 vdex_DexEndOffset(const u1 *);
const u1 *vdex_GetNextDexFileData(const u1 *, u4 *);
u4 vdex_GetLocationChecksum(const u1 *, u4);
const u1 *vdex_GetVerifierDepsData(const u1 *);
u4 vdex_GetVerifierDepsDataOffset(const u1 *);
u4 vdex_GetVerifierDepsDataSize(const u1 *);
const u1 *vdex_GetQuickeningInfo(const u1 *);
u4 vdex_GetQuickeningInfoSize(const u1 *);
u4 vdex_GetQuickeningInfoOffset(const u1 *);

void vdex_dumpHeaderInfo(const u1 *);
bool vdex_Unquicken(const u1 *);

#endif
