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

#ifndef _VDEX_COMMON_H_
#define _VDEX_COMMON_H_

#include "../common.h"

#define kUnresolvedMarker (u2)(-1)

static const u1 kVdexMagic[] = { 'v', 'd', 'e', 'x' };

typedef u4 VdexChecksum;
typedef u4 QuickeningTableOffsetType;

typedef struct {
  const u1 *data;  // Pointer to data begin
  u4 size;         // Size of data (in bytes)
  u4 offset;       // Offset from Vdex begin
} vdex_data_array_t;

#endif
