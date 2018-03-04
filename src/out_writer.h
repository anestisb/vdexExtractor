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

#ifndef _OUT_WRITER_H_
#define _OUT_WRITER_H_

#include "common.h"

void outWriter_formatName(char *, size_t, const char *, const char *, size_t, const char *);

bool outWriter_DexFile(const runArgs_t *, const char *, size_t, const u1 *, size_t);

bool outWriter_VdexFile(const runArgs_t *, const char *, u1 *, off_t);

#endif
