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

#ifndef _VDEX_BACKEND_019_H_
#define _VDEX_BACKEND_019_H_

#include "../common.h"
#include "../dex.h"
#include "vdex_019.h"

typedef struct __attribute__((packed)) {
  vdexDepStrings_019 extraStrings;
  vdexDepTypeSet_019 assignTypeSets;
  vdexDepTypeSet_019 unassignTypeSets;
  vdexDepClassResSet_019 classes;
  vdexDepFieldResSet_019 fields;
  vdexDepMethodResSet_019 methods;
  vdexDepUnvfyClassesSet_019 unvfyClasses;
} vdexDepData_019;

typedef struct __attribute__((packed)) {
  u4 numberOfDexFiles;
  vdexDepData_019 *pVdexDepData;
} vdexDeps_019;

void vdex_backend_019_dumpDepsInfo(const u1 *);
int vdex_backend_019_process(const char *, const u1 *, size_t, const runArgs_t *);

#endif
