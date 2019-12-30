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

#ifndef _VDEX_BACKEND_021_H_
#define _VDEX_BACKEND_021_H_

#include "../common.h"
#include "../dex.h"
#include "vdex_021.h"

typedef struct __attribute__((packed)) {
  vdexDepStrings_021 extraStrings;
  vdexDepTypeSet_021 assignTypeSets;
  vdexDepTypeSet_021 unassignTypeSets;
  vdexDepClassResSet_021 classes;
  vdexDepFieldResSet_021 fields;
  vdexDepMethodResSet_021 methods;
  vdexDepUnvfyClassesSet_021 unvfyClasses;
} vdexDepData_021;

typedef struct __attribute__((packed)) {
  u4 numberOfDexFiles;
  vdexDepData_021 *pVdexDepData;
} vdexDeps_021;

void vdex_backend_021_dumpDepsInfo(const u1 *);
int vdex_backend_021_process(const char *, const u1 *, size_t, const runArgs_t *);

#endif
