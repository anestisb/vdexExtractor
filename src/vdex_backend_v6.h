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

#ifndef _VDEX_BACKEND_V6_H_
#define _VDEX_BACKEND_V6_H_

#include "common.h"
#include "dex.h"
#include "vdex.h"

typedef struct __attribute__((packed)) {
  vdexDepStrings extraStrings;
  vdexDepTypeSet assignTypeSets;
  vdexDepTypeSet unassignTypeSets;
  vdexDepClassResSet classes;
  vdexDepFieldResSet fields;
  vdexDepMethodResSet directMethods;
  vdexDepMethodResSet virtualMethods;
  vdexDepMethodResSet interfaceMethods;
  vdexDepUnvfyClassesSet unvfyClasses;
} vdexDepData_v6;

typedef struct __attribute__((packed)) {
  u4 numberOfDexFiles;
  vdexDepData_v6 *pVdexDepData;
} vdexDeps_v6;

void *vdex_initDepsInfo_v6(const u1 *);
void vdex_destroyDepsInfo_v6(const void *);
void vdex_dumpDepsInfo_v6(const u1 *, const void *);

int vdex_process_v6(const char *, const u1 *, const runArgs_t *);

#endif
