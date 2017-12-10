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

#ifndef _VDEX_BACKEND_V10_H_
#define _VDEX_BACKEND_V10_H_

#include "common.h"
#include "dex.h"
#include "vdex.h"

typedef struct __attribute__((packed)) {
  vdexDepStrings extraStrings;
  vdexDepTypeSet assignTypeSets;
  vdexDepTypeSet unassignTypeSets;
  vdexDepClassResSet classes;
  vdexDepFieldResSet fields;
  vdexDepMethodResSet methods;
  vdexDepUnvfyClassesSet unvfyClasses;
} vdexDepData_v10;

typedef struct __attribute__((packed)) {
  u4 numberOfDexFiles;
  vdexDepData_v10 *pVdexDepData;
} vdexDeps_v10;

void *vdex_initDepsInfo_v10(const u1 *);
void vdex_destroyDepsInfo_v10(const void *);
void vdex_dumpDepsInfo_v10(const u1 *, const void *);

int vdex_process_v10(const char *, const u1 *, const runArgs_t *);

#endif
