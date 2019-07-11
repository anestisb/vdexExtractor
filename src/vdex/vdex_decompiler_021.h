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

#ifndef _VDEX_DECOMPILER_021_H_
#define _VDEX_DECOMPILER_021_H_

#include "../common.h"
#include "../dex.h"
#include "../dex_instruction.h"
#include "vdex_common.h"

// Dex decompiler driver function using quicken_info data
bool vdex_decompiler_021_decompile(const u1 *, dexMethod *, const vdex_data_array_t *, bool);

// Dex decompiler walk method that simply disassembles code blocks
void vdex_decompiler_021_walk(const u1 *, dexMethod *);

#endif
