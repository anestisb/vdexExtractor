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

#ifndef _LOG_H_
#define _LOG_H_

#include "common.h"

typedef enum { l_FATAL = 0, l_ERROR, l_WARN, l_INFO, l_DEBUG, l_MAX_LEVEL } log_level_t;

void log_setMinLevel(log_level_t);
void log_setDisStatus(bool);
bool log_getDisStatus();
bool log_initLogFile(const char *);
void log_closeLogFile();

void log_msg(log_level_t, bool, bool, bool, const char *, const char *, int, const char *, ...);
void log_dis(const char *fmt, ...);
void log_raw(const char *fmt, ...);

#define LOGMSG(ll, ...) \
  log_msg(ll, false, false, false, __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__);
#define LOGMSG_P(ll, ...) \
  log_msg(ll, true, false, false, __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__);
#define LOGMSG_RAW(ll, ...) \
  log_msg(ll, false, true, false, __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__);
#define DISPLAY(ll, ...) \
  log_msg(ll, false, false, true, __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__);

#endif
