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

#ifndef _VDEX_019_H_
#define _VDEX_019_H_

#include "../common.h"
#include "../dex.h"
#include "vdex_common.h"

static const u1 kVdexDepsVer_019[] = { '0', '1', '9', '\0' };
static const u1 kVdexDexSectVer_019[] = { '0', '0', '2', '\0' };
static const u1 kDexSectVerEmpty_019[] = { '0', '0', '0', '\0' };

typedef struct __attribute__((packed)) {
  u1 magic[4];
  u1 verifierDepsVersion[4];
  u1 dexSectionVersion[4];
  u4 numberOfDexFiles;
  u4 verifierDepsSize;
} vdexHeader_019;

typedef struct __attribute__((packed)) {
  u4 dexSize;
  u4 dexSharedDataSize;
  u4 quickeningInfoSize;
} vdexDexSectHeader_019;

// VDEX files contain extracted DEX files. The VdexFile class maps the file to
// memory and provides tools for accessing its individual sections.
//
// File format:
//   VdexFile::VerifierDepsHeader    fixed-length header
//      Dex file checksums
//
//   Optionally:
//      VdexFile::DexSectionHeader   fixed-length header
//
//      quicken_table_off[0]  offset into QuickeningInfo section for offset table for DEX[0].
//      DEX[0]                array of the input DEX files, the bytecode may have been quickened.
//      quicken_table_off[1]
//      DEX[1]
//      ...
//      DEX[D]
//
//   VerifierDeps
//      uint8[D][]                 verification dependencies
//
//   Optionally:
//      QuickeningInfo
//        uint8[D][]                  quickening data
//        uint32[D][]                 quickening data offset tables

typedef struct __attribute__((packed)) {
  vdexHeader_019 *pVdexHeader;
  dexHeader *pDexFiles;
} vdexFile_019;

typedef struct __attribute__((packed)) {
  u4 numberOfStrings;
  const char **strings;
} vdexDepStrings_019;

typedef struct __attribute__((packed)) {
  u4 dstIndex;
  u4 srcIndex;
} vdexDepSet_019;

typedef struct __attribute__((packed)) {
  u2 typeIdx;
  u2 accessFlags;
} vdexDepClassRes_019;

typedef struct __attribute__((packed)) {
  u4 numberOfEntries;
  vdexDepSet_019 *pVdexDepSets;
} vdexDepTypeSet_019;

typedef struct __attribute__((packed)) {
  u4 fieldIdx;
  u2 accessFlags;
  u4 declaringClassIdx;
} vdexDepFieldRes_019;

typedef struct __attribute__((packed)) {
  u4 methodIdx;
  u2 accessFlags;
  u4 declaringClassIdx;
} vdexDepMethodRes_019;

typedef struct __attribute__((packed)) {
  u2 typeIdx;
} vdexDepUnvfyClass_019;

typedef struct __attribute__((packed)) {
  u4 numberOfEntries;
  vdexDepClassRes_019 *pVdexDepClasses;
} vdexDepClassResSet_019;

typedef struct __attribute__((packed)) {
  u4 numberOfEntries;
  vdexDepFieldRes_019 *pVdexDepFields;
} vdexDepFieldResSet_019;

typedef struct __attribute__((packed)) {
  u4 numberOfEntries;
  vdexDepMethodRes_019 *pVdexDepMethods;
} vdexDepMethodResSet_019;

typedef struct __attribute__((packed)) {
  u4 numberOfEntries;
  vdexDepUnvfyClass_019 *pVdexDepUnvfyClasses;
} vdexDepUnvfyClassesSet_019;

// Verify if valid Vdex file
bool vdex_019_isValidVdex(const u1 *);
bool vdex_019_isMagicValid(const u1 *);
bool vdex_019_isVersionValid(const u1 *);

bool vdex_019_hasDexSection(const u1 *);
u4 vdex_019_GetSizeOfChecksumsSection(const u1 *);
const u1 *vdex_019_DexBegin(const u1 *);
u4 vdex_019_DexBeginOffset(const u1 *);
const u1 *vdex_019_DexEnd(const u1 *);
u4 vdex_019_DexEndOffset(const u1 *);
const u1 *vdex_019_GetNextDexFileData(const u1 *, u4 *);
u4 vdex_019_GetLocationChecksum(const u1 *, u4);
void vdex_019_SetLocationChecksum(const u1 *, u4, u4);
void vdex_019_GetVerifierDeps(const u1 *, vdex_data_array_t *);
void vdex_019_GetQuickeningInfo(const u1 *, vdex_data_array_t *);

u4 vdex_019_GetDexSectionHeaderOffset(const u1 *);
const vdexDexSectHeader_019 *vdex_019_GetDexSectionHeader(const u1 *);

// Vdex 019 introduces an intermediate set of tables that contain the QuickeningInfo offsets for
// each Dex file in the container
void vdex_019_GetQuickenInfoOffsetTable(const u1 *, const vdex_data_array_t *, vdex_data_array_t *);

void vdex_019_dumpHeaderInfo(const u1 *);
void vdex_019_dumpDepsInfo(const u1 *);
bool vdex_019_SanityCheck(const u1 *, size_t);
int vdex_019_process(const char *, const u1 *, size_t, const runArgs_t *);

#endif
