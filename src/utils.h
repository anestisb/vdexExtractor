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

#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdint.h>

bool utils_init(infiles_t *);

uint8_t *utils_mapFileToRead(char *, off_t *, int *);

bool utils_writeToFd(int, const uint8_t *, off_t);

void utils_hexDump(char *, const uint8_t *, int);

char *util_bin2hex(const unsigned char *, const size_t);

#endif
