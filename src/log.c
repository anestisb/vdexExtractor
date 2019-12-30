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

#include "log.h"

#include <stdarg.h>
#include <sys/time.h>
#include <time.h>

#include "common.h"

static unsigned int log_minLevel;
static bool log_isTTY;
static bool inside_line;
static bool dis_enabled;
static int log_fd;
static FILE *log_disOut;

__attribute__((constructor)) void log_init(void) {
  log_minLevel = l_INFO;
  log_fd = STDOUT_FILENO;
  log_isTTY = isatty(log_fd);
  log_disOut = stdout;
}

void log_setMinLevel(log_level_t dl) { log_minLevel = dl; }
void log_setDisStatus(bool status) { dis_enabled = status; }
bool log_getDisStatus() { return dis_enabled; }

bool log_initLogFile(const char *logFile) {
  if (logFile == NULL) {
    return true;
  }

  log_disOut = fopen(logFile, "ab+");
  if (log_disOut == NULL) {
    log_disOut = stdout;
    LOGMSG_P(l_ERROR, "Couldn't open logFile '%s'", logFile);
    return false;
  }
  return true;
}

void log_closeLogFile() {
  fflush(log_disOut);
  if (log_disOut != stdout) {
    fclose(log_disOut);
  }
}

void log_msg(log_level_t dl,
             bool perr,
             bool raw_print,
             bool is_display,
             const char *file,
             const char *func,
             int line,
             const char *fmt,
             ...) {
  struct {
    char *descr;
    char *prefix;
  } logLevels[] = { { "[FATAL]", "\033[1;31m" },
                    { "[ERROR]", "\033[1;35m" },
                    { "[WARNING]", "\033[1;33m" },
                    { "[INFO]", "\033[1m" },
                    { "[DEBUG]", "\033[0;37m" } };

  char strerr[512];
  if (perr) {
    snprintf(strerr, sizeof(strerr), "%s", strerror(errno));
  }

  if (dl > log_minLevel) return;

  // stdout might be used from disassembler output. If so, flush before writing generic log entry
  if (dis_enabled && log_disOut == stdout) fflush(log_disOut);

  // Explicitly print display messages always to stdout and not to log file (if set)
  int curLogFd = log_fd;
  if (is_display) {
    curLogFd = STDOUT_FILENO;
  }

  struct tm tm;
  struct timeval tv;

  gettimeofday(&tv, NULL);
  localtime_r((const time_t *)&tv.tv_sec, &tm);

  if (inside_line && !raw_print) {
    dprintf(curLogFd, "\n");
  }

  if (log_isTTY) {
    dprintf(curLogFd, "%s", logLevels[dl].prefix);
  }

  if (raw_print) {
    int fmtLen = strlen(fmt);
    if (fmtLen > 0 && fmt[fmtLen - 1] == '\n') {
      inside_line = false;
    } else {
      inside_line = true;
    }
  } else {
    if (!is_display && (log_minLevel >= l_DEBUG || !log_isTTY)) {
      dprintf(curLogFd, "%s [%d] %d/%02d/%02d %02d:%02d:%02d (%s:%d %s) ", logLevels[dl].descr,
              getpid(), tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min,
              tm.tm_sec, file, line, func);
    } else {
      dprintf(curLogFd, "%s ", logLevels[dl].descr);
    }
  }

  va_list args;
  va_start(args, fmt);
  vdprintf(curLogFd, fmt, args);
  va_end(args);

  if (perr) {
    dprintf(curLogFd, ": %s", strerr);
  }

  if (log_isTTY) {
    dprintf(curLogFd, "\033[0m");
  }

  if (!raw_print) dprintf(curLogFd, "\n");

  if (dl == l_FATAL) {
    exitWrapper(EXIT_FAILURE);
  }
}

void log_dis(const char *fmt, ...) {
  if (!dis_enabled) return;
  va_list args;
  va_start(args, fmt);
  vfprintf(log_disOut, fmt, args);
  va_end(args);
}

void log_raw(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  vfprintf(stdout, fmt, args);
  va_end(args);
}
