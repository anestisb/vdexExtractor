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

#ifndef _COMMON_H_
#define _COMMON_H_

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <limits.h>
#include <errno.h>
#include <string.h>

#define PROG_NAME    "vdexExtractor"
#define PROG_VERSION "0.1.0"
#define PROG_AUTHORS "    Anestis Bechtsoudis <anestis@census-labs.com>\n"\
                     "  Copyright 2017 by CENSUS S.A. All Rights Reserved."

#define AB         ANSI_BOLD
#define AC         ANSI_CLEAR
#define ANSI_BOLD  "\033[1m"
#define ANSI_CLEAR "\033[0m"

typedef struct {
    char *inputFile;
    char **files;
    size_t fileCnt;
} infiles_t;

#endif
