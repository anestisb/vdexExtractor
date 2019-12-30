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

#ifndef _VDEX_010_H_
#define _VDEX_010_H_

#include "../common.h"
#include "../dex.h"
#include "vdex_common.h"

static const u1 kVdex010[] = { '0', '1', '0', '\0' };

typedef struct __attribute__((packed)) {
  u1 magic[4];
  u1 version[4];
  u4 numberOfDexFiles;
  u4 dexSize;
  u4 verifierDepsSize;
  u4 quickeningInfoSize;
} vdexHeader_010;

// VDEX files contain extracted DEX files. The VdexFile class maps the file to
// memory and provides tools for accessing its individual sections.
//
// File format:
//   VdexFile::Header    fixed-length header
//
//   DEX[0]              array of the input DEX files
//   DEX[1]              the bytecode may have been quickened
//   ...
//   DEX[D]
//   QuickeningInfo
//     uint8[]                     quickening data
//     unaligned_uint32_t[2][]     table of offsets pair:
//                                    uint32_t[0] contains code_item_offset
//                                    uint32_t[1] contains quickening data offset from the start
//                                                of QuickeningInfo
//     unalgined_uint32_t[D]       start offsets (from the start of QuickeningInfo) in previous
//                                 table for each dex file

typedef struct __attribute__((packed)) {
  vdexHeader_010 *pVdexHeader;
  dexHeader *pDexFiles;
} vdexFile_010;

typedef struct __attribute__((packed)) {
  u4 numberOfStrings;
  const char **strings;
} vdexDepStrings_010;

typedef struct __attribute__((packed)) {
  u4 dstIndex;
  u4 srcIndex;
} vdexDepSet_010;

typedef struct __attribute__((packed)) {
  u2 typeIdx;
  u2 accessFlags;
} vdexDepClassRes_010;

typedef struct __attribute__((packed)) {
  u4 numberOfEntries;
  vdexDepSet_010 *pVdexDepSets;
} vdexDepTypeSet_010;

typedef struct __attribute__((packed)) {
  u4 fieldIdx;
  u2 accessFlags;
  u4 declaringClassIdx;
} vdexDepFieldRes_010;

typedef struct __attribute__((packed)) {
  u4 methodIdx;
  u2 accessFlags;
  u4 declaringClassIdx;
} vdexDepMethodRes_010;

typedef struct __attribute__((packed)) {
  u2 typeIdx;
} vdexDepUnvfyClass_010;

typedef struct __attribute__((packed)) {
  u4 numberOfEntries;
  vdexDepClassRes_010 *pVdexDepClasses;
} vdexDepClassResSet_010;

typedef struct __attribute__((packed)) {
  u4 numberOfEntries;
  vdexDepFieldRes_010 *pVdexDepFields;
} vdexDepFieldResSet_010;

typedef struct __attribute__((packed)) {
  u4 numberOfEntries;
  vdexDepMethodRes_010 *pVdexDepMethods;
} vdexDepMethodResSet_010;

typedef struct __attribute__((packed)) {
  u4 numberOfEntries;
  vdexDepUnvfyClass_010 *pVdexDepUnvfyClasses;
} vdexDepUnvfyClassesSet_010;

// Verify if valid Vdex file
bool vdex_010_isValidVdex(const u1 *);
bool vdex_010_isMagicValid(const u1 *);
bool vdex_010_isVersionValid(const u1 *);

bool vdex_010_hasDexSection(const u1 *);
u4 vdex_010_GetSizeOfChecksumsSection(const u1 *);
const u1 *vdex_010_DexBegin(const u1 *);
u4 vdex_010_DexBeginOffset(const u1 *);
const u1 *vdex_010_DexEnd(const u1 *);
u4 vdex_010_DexEndOffset(const u1 *);
const u1 *vdex_010_GetNextDexFileData(const u1 *, u4 *);
u4 vdex_010_GetLocationChecksum(const u1 *, u4);
void vdex_010_SetLocationChecksum(const u1 *, u4, u4);
void vdex_010_GetVerifierDeps(const u1 *, vdex_data_array_t *);
void vdex_010_GetQuickeningInfo(const u1 *, vdex_data_array_t *);

void vdex_010_dumpHeaderInfo(const u1 *);
void vdex_010_dumpDepsInfo(const u1 *);
bool vdex_010_SanityCheck(const u1 *, size_t);
int vdex_010_process(const char *, const u1 *, size_t, const runArgs_t *);

#endif
