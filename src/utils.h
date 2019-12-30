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

#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdint.h>

#include "common.h"

bool utils_init(infiles_t *);
u1 *utils_mapFileToRead(const char *, off_t *, int *);
bool utils_writeToFd(int, const u1 *, off_t);
void utils_hexDump(char *, const u1 *, int);
char *utils_bin2hex(const unsigned char *, const size_t);
void *utils_malloc(size_t);
void *utils_calloc(size_t);
void *utils_realloc(void *, size_t);
void *utils_crealloc(void *ptr, size_t, size_t);

// To simplify api, all errors are treated as fatal
void utils_pseudoStrAppend(const char **, size_t *, size_t *, const char *);

void utils_startTimer(struct timespec *);
long utils_endTimer(struct timespec *);

u4 *utils_processFileWithCsums(const char *, int *);

char *utils_fileBasename(char const *);
bool utils_isValidDir(const char *);

uintptr_t utils_roundDown(uintptr_t, uintptr_t);
uintptr_t utils_roundUp(uintptr_t, uintptr_t);
uintptr_t utils_allignUp(uintptr_t, uintptr_t);

#endif
