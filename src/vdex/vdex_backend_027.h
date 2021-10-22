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

#ifndef _VDEX_BACKEND_027_H_
#define _VDEX_BACKEND_027_H_

#include "../common.h"
#include "../dex.h"
#include "vdex_027.h"

typedef struct __attribute__((packed)) {
  vdexDepStrings_027 extraStrings;
  vdexDepTypeSet_027 assignTypeSets;
  vdexDepTypeSet_027 unassignTypeSets;
  vdexDepClassResSet_027 classes;
  vdexDepFieldResSet_027 fields;
  vdexDepMethodResSet_027 methods;
  vdexDepUnvfyClassesSet_027 unvfyClasses;
} vdexDepData_027;

typedef struct __attribute__((packed)) {
  u4 numberOfDexFiles;
  vdexDepData_027 *pVdexDepData;
} vdexDeps_027;

void vdex_backend_027_dumpDepsInfo(const u1 *);
int vdex_backend_027_process(const char *, const u1 *, size_t, const runArgs_t *);

#endif
