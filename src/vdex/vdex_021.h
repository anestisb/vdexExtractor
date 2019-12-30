/*

   vdexExtractor
   -----------------------------------------

   Anestis Bechtsoudis <anestis@census-labs.com>
   Copyright 2017 - 2020 by CENSUS S.A. All Rights Reserved.

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

#ifndef _VDEX_021_H_
#define _VDEX_021_H_

#include "../common.h"
#include "../dex.h"
#include "vdex_common.h"

static const u1 kVdexDepsVer_021[] = { '0', '2', '1', '\0' };
static const u1 kVdexDexSectVer_021[] = { '0', '0', '2', '\0' };
static const u1 kDexSectVerEmpty_021[] = { '0', '0', '0', '\0' };

typedef struct __attribute__((packed)) {
  u1 magic[4];
  u1 verifierDepsVersion[4];
  u1 dexSectionVersion[4];
  u4 numberOfDexFiles;
  u4 verifierDepsSize;
  u4 bootclasspathChecksumsSize;
  u4 classLoaderContextSize;
} vdexHeader_021;

typedef struct __attribute__((packed)) {
  u4 dexSize;
  u4 dexSharedDataSize;
  u4 quickeningInfoSize;
} vdexDexSectHeader_021;

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
  vdexHeader_021 *pVdexHeader;
  dexHeader *pDexFiles;
} vdexFile_021;

typedef struct __attribute__((packed)) {
  u4 numberOfStrings;
  const char **strings;
} vdexDepStrings_021;

typedef struct __attribute__((packed)) {
  u4 dstIndex;
  u4 srcIndex;
} vdexDepSet_021;

typedef struct __attribute__((packed)) {
  u2 typeIdx;
  u2 accessFlags;
} vdexDepClassRes_021;

typedef struct __attribute__((packed)) {
  u4 numberOfEntries;
  vdexDepSet_021 *pVdexDepSets;
} vdexDepTypeSet_021;

typedef struct __attribute__((packed)) {
  u4 fieldIdx;
  u2 accessFlags;
  u4 declaringClassIdx;
} vdexDepFieldRes_021;

typedef struct __attribute__((packed)) {
  u4 methodIdx;
  u2 accessFlags;
  u4 declaringClassIdx;
} vdexDepMethodRes_021;

typedef struct __attribute__((packed)) {
  u2 typeIdx;
} vdexDepUnvfyClass_021;

typedef struct __attribute__((packed)) {
  u4 numberOfEntries;
  vdexDepClassRes_021 *pVdexDepClasses;
} vdexDepClassResSet_021;

typedef struct __attribute__((packed)) {
  u4 numberOfEntries;
  vdexDepFieldRes_021 *pVdexDepFields;
} vdexDepFieldResSet_021;

typedef struct __attribute__((packed)) {
  u4 numberOfEntries;
  vdexDepMethodRes_021 *pVdexDepMethods;
} vdexDepMethodResSet_021;

typedef struct __attribute__((packed)) {
  u4 numberOfEntries;
  vdexDepUnvfyClass_021 *pVdexDepUnvfyClasses;
} vdexDepUnvfyClassesSet_021;

// Verify if valid Vdex file
bool vdex_021_isValidVdex(const u1 *);
bool vdex_021_isMagicValid(const u1 *);
bool vdex_021_isVersionValid(const u1 *);

bool vdex_021_hasDexSection(const u1 *);
u4 vdex_021_GetSizeOfChecksumsSection(const u1 *);
const u1 *vdex_021_DexBegin(const u1 *);
u4 vdex_021_DexBeginOffset(const u1 *);
const u1 *vdex_021_DexEnd(const u1 *);
u4 vdex_021_DexEndOffset(const u1 *);
const u1 *vdex_021_GetNextDexFileData(const u1 *, u4 *);
u4 vdex_021_GetLocationChecksum(const u1 *, u4);
void vdex_021_SetLocationChecksum(const u1 *, u4, u4);
void vdex_021_GetVerifierDeps(const u1 *, vdex_data_array_t *);
void vdex_021_GetQuickeningInfo(const u1 *, vdex_data_array_t *);
void vdex_021_GetBootClassPathChecksumData(const u1 *, vdex_data_array_t *);
void vdex_021_GetClassLoaderContextData(const u1 *, vdex_data_array_t *);

u4 vdex_021_GetDexSectionHeaderOffset(const u1 *);
const vdexDexSectHeader_021 *vdex_021_GetDexSectionHeader(const u1 *);

// Vdex 021 introduces an intermediate set of tables that contain the QuickeningInfo offsets for
// each Dex file in the container
void vdex_021_GetQuickenInfoOffsetTable(const u1 *, const vdex_data_array_t *, vdex_data_array_t *);

void vdex_021_dumpHeaderInfo(const u1 *);
void vdex_021_dumpDepsInfo(const u1 *);
bool vdex_021_SanityCheck(const u1 *, size_t);
int vdex_021_process(const char *, const u1 *, size_t, const runArgs_t *);

#endif
