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

#ifndef _VDEX_027_H_
#define _VDEX_027_H_

#include "../common.h"
#include "../dex.h"
#include "vdex_common.h"

static const u1 kVdexVersion_027[] = { '0', '2', '7', '\0' };
static const u4 kNumberOfSections_027 = 4;

// VDEX files contain extracted DEX files. The VdexFile class maps the file to
// memory and provides tools for accessing its individual sections.
//
// In the description below, D is the number of dex files.
//
// File format:
//   VdexFileHeader    fixed-length header
//   VdexSectionHeader[kNumberOfSections]
//
//   Checksum section
//     VdexChecksum[D]
//
//   Optionally:
//      DexSection
//          DEX[0]                array of the input DEX files
//          DEX[1]
//          ...
//          DEX[D-1]
//
//   VerifierDeps
//      4-byte alignment
//      uint32[D]                  DexFileDeps offsets for each dex file
//      DexFileDeps[D][]           verification dependencies
//        4-byte alignment
//        uint32[class_def_size]     TypeAssignability offsets (kNotVerifiedMarker for a class
//                                        that isn't verified)
//        uint32                     Offset of end of AssignabilityType sets
//        uint8[]                    AssignabilityType sets
//        4-byte alignment
//        uint32                     Number of strings
//        uint32[]                   String data offsets for each string
//        uint8[]                    String data

typedef struct __attribute__((packed)) {
  u1 magic[4];
  u1 vdexVersion[4];
  u4 numberOfSections;
} vdexHeader_027;

typedef struct __attribute__((packed)) {
  u4 sectionKind;
  u4 sectionOffset;
  u4 sectionSize;
} vdexSectionHeader_027;

typedef struct __attribute__((packed)) {
  vdexHeader_027 *pVdexHeader;
  dexHeader *pDexFiles;
} vdexFile_027;

typedef struct __attribute__((packed)) {
  u4 numberOfStrings;
  const char **strings;
} vdexDepStrings_027;

typedef struct __attribute__((packed)) {
  u4 dstIndex;
  u4 srcIndex;
} vdexDepSet_027;

typedef struct __attribute__((packed)) {
  u2 typeIdx;
  u2 accessFlags;
} vdexDepClassRes_027;

typedef struct __attribute__((packed)) {
  u4 numberOfEntries;
  vdexDepSet_027 *pVdexDepSets;
} vdexDepTypeSet_027;

typedef struct __attribute__((packed)) {
  u4 fieldIdx;
  u2 accessFlags;
  u4 declaringClassIdx;
} vdexDepFieldRes_027;

typedef struct __attribute__((packed)) {
  u4 methodIdx;
  u2 accessFlags;
  u4 declaringClassIdx;
} vdexDepMethodRes_027;

typedef struct __attribute__((packed)) {
  u2 typeIdx;
} vdexDepUnvfyClass_027;

typedef struct __attribute__((packed)) {
  u4 numberOfEntries;
  vdexDepClassRes_027 *pVdexDepClasses;
} vdexDepClassResSet_027;

typedef struct __attribute__((packed)) {
  u4 numberOfEntries;
  vdexDepFieldRes_027 *pVdexDepFields;
} vdexDepFieldResSet_027;

typedef struct __attribute__((packed)) {
  u4 numberOfEntries;
  vdexDepMethodRes_027 *pVdexDepMethods;
} vdexDepMethodResSet_027;

typedef struct __attribute__((packed)) {
  u4 numberOfEntries;
  vdexDepUnvfyClass_027 *pVdexDepUnvfyClasses;
} vdexDepUnvfyClassesSet_027;

// Verify if valid Vdex file
bool vdex_027_isValidVdex(const u1 *);
bool vdex_027_isMagicValid(const u1 *);
bool vdex_027_isVersionValid(const u1 *);

const vdexSectionHeader_027 *vdex_027_GetSectionHeader(const u1 *, u4);
bool vdex_027_hasDexSection(const u1 *);
u4 vdex_027_GetNumberOfDexFiles(const u1 *);
const u1 *vdex_027_DexBegin(const u1 *);
u4 vdex_027_DexBeginOffset(const u1 *);
const u1 *vdex_027_DexEnd(const u1 *);
u4 vdex_027_DexEndOffset(const u1 *);
const u1 *vdex_027_GetNextDexFileData(const u1 *, u4 *);
u4 vdex_027_GetLocationChecksum(const u1 *, u4);
void vdex_027_SetLocationChecksum(const u1 *, u4, u4);

void vdex_027_dumpHeaderInfo(const u1 *);
void vdex_027_dumpDepsInfo(const u1 *);
bool vdex_027_SanityCheck(const u1 *, size_t);
int vdex_027_process(const char *, const u1 *, size_t, const runArgs_t *);

#endif
