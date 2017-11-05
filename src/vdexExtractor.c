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

#include <getopt.h>
#include <libgen.h>
#include <sys/mman.h>

#include "common.h"
#include "log.h"
#include "utils.h"
#include "vdex.h"

// exit() wrapper
void exitWrapper(int errCode) {
  log_closeLogFile();
  log_closeRecoverFile();
  exit(errCode);
}

// clang-format off
static void usage(bool exit_success) {
  LOGMSG_RAW(l_INFO, "              " PROG_NAME " ver. " PROG_VERSION "\n");
  LOGMSG_RAW(l_INFO, PROG_AUTHORS "\n\n");
  LOGMSG_RAW(l_INFO,"%s",
             " -i, --input=<path>   : input dir (1 max depth) or single file\n"
             " -o, --output=<path>  : output path (default is same as input)\n"
             " -f, --file-override  : allow output file override if already exists\n"
             " -u, --unquicken      : enable unquicken bytecode decompiler\n"
             " -D, --dump-deps      : dump verified dependencies information\n"
             " -d, --disassemble    : enable bytecode disassembler\n"
             " -r, --class-recover  : dump information useful to recover original class name (json "
                                     "file to output path)\n"
             " -v, --debug=LEVEL    : log level (0 - FATAL ... 4 - DEBUG), default: '3' (INFO)\n"
             " -l, --log-file=<path>: save disassembler and/or verified dependencies output to log "
                                     "file (default is STDOUT)\n"
             " -h, --help           : this help\n");

  if (exit_success)
    exitWrapper(EXIT_SUCCESS);
  else
    exitWrapper(EXIT_FAILURE);
}
// clang-format on

int main(int argc, char **argv) {
  int c;
  int logLevel = l_INFO;
  const char *logFile = NULL;
  runArgs_t pRunArgs = {
    .outputDir = NULL,
    .fileOverride = false,
    .unquicken = false,
    .enableDisassembler = false,
    .dumpDeps = false,
    .classRecover = false,
  };
  infiles_t pFiles = {
    .inputFile = NULL, .files = NULL, .fileCnt = 0,
  };

  if (argc < 1) usage(true);

  struct option longopts[] = { { "input", required_argument, 0, 'i' },
                               { "output", required_argument, 0, 'o' },
                               { "file-override", no_argument, 0, 'f' },
                               { "unquicken", no_argument, 0, 'u' },
                               { "disassemble", no_argument, 0, 'd' },
                               { "dump-deps", no_argument, 0, 'D' },
                               { "class-recover", no_argument, 0, 'r' },
                               { "debug", required_argument, 0, 'v' },
                               { "log-file", required_argument, 0, 'l' },
                               { "help", no_argument, 0, 'h' },
                               { 0, 0, 0, 0 } };

  while ((c = getopt_long(argc, argv, "i:o:fudDrv:l:h", longopts, NULL)) != -1) {
    switch (c) {
      case 'i':
        pFiles.inputFile = optarg;
        break;
      case 'o':
        pRunArgs.outputDir = optarg;
        break;
      case 'f':
        pRunArgs.fileOverride = true;
        break;
      case 'u':
        pRunArgs.unquicken = true;
        break;
      case 'd':
        pRunArgs.enableDisassembler = true;
        log_setDisStatus(true);
        break;
      case 'D':
        pRunArgs.dumpDeps = true;
        log_setDisStatus(true);
        break;
      case 'r':
        pRunArgs.classRecover = true;
        pRunArgs.enableDisassembler = true;
        break;
      case 'v':
        logLevel = atoi(optarg);
        break;
      case 'l':
        logFile = optarg;
        break;
      case 'h':
        usage(true);
        break;
      default:
        exitWrapper(EXIT_FAILURE);
        break;
    }
  }

  // We don't want to increase the complexity of the unquicken decompiler, so offer class name
  // recover checks only when simply walking the Vdex file
  if (pRunArgs.unquicken && pRunArgs.classRecover) {
    LOGMSG(l_FATAL, "Class name recover cannot be used in parallel with unquicken decompiler");
  }

  // Adjust log level
  if (logLevel < 0 || logLevel >= l_MAX_LEVEL) {
    LOGMSG(l_FATAL, "Invalid debug level '%d'", logLevel);
  }
  log_setMinLevel(logLevel);

  // Set log file
  if (log_initLogFile(logFile) == false) {
    LOGMSG(l_FATAL, "Failed to initialize log file");
    exitWrapper(EXIT_FAILURE);
  }

  // Initialize input files
  if (!utils_init(&pFiles)) {
    LOGMSG(l_FATAL, "Couldn't load input files");
    exitWrapper(EXIT_FAILURE);
  }

  size_t processedVdexCnt = 0, processedDexCnt = 0;
  DISPLAY(l_INFO, "Processing %zu file(s) from %s", pFiles.fileCnt, pFiles.inputFile);

  for (size_t f = 0; f < pFiles.fileCnt; f++) {
    off_t fileSz = 0;
    int srcfd = -1;
    u1 *buf = NULL;

    LOGMSG(l_DEBUG, "Processing '%s'", pFiles.files[f]);

    // mmap file
    buf = utils_mapFileToRead(pFiles.files[f], &fileSz, &srcfd);
    if (buf == NULL) {
      LOGMSG(l_ERROR, "Open & map failed - skipping '%s'", pFiles.files[f]);
      continue;
    }

    // Quick size checks for minimum valid file
    if ((size_t)fileSz < (sizeof(vdexHeader) + sizeof(dexHeader))) {
      LOGMSG(l_WARN, "Invalid input file - skipping '%s'", pFiles.files[f]);
      munmap(buf, fileSz);
      close(srcfd);
      continue;
    }

    // Validate Vdex magic header
    if (!vdex_isValidVdex(buf)) {
      LOGMSG(l_WARN, "Invalid Vdex header - skipping '%s'", pFiles.files[f]);
      munmap(buf, fileSz);
      close(srcfd);
      continue;
    }
    vdex_dumpHeaderInfo(buf);

    // Dump Vdex verified dependencies info
    if (pRunArgs.dumpDeps) {
      vdexDeps *pVdexDeps = vdex_initDepsInfo(buf);
      if (pVdexDeps == NULL) {
        LOGMSG(l_WARN, "Empty verified dependency data")
      } else {
        vdex_dumpDepsInfo(buf, pVdexDeps);
        vdex_destroyDepsInfo(pVdexDeps);
      }
    }

    // Unquicken Dex bytecode or simply walk optimized Dex files
    int ret = vdex_process(pFiles.files[f], buf, &pRunArgs);
    if (ret == -1) {
      LOGMSG(l_ERROR, "Failed to process Dex files - skipping '%s'", pFiles.files[f]);
      munmap(buf, fileSz);
      close(srcfd);
      continue;
    }

    processedDexCnt += ret;
    processedVdexCnt++;

    // Clean-up
    munmap(buf, fileSz);
    buf = NULL;
    close(srcfd);
  }

  free(pFiles.files);
  DISPLAY(l_INFO, "%u out of %u Vdex files have been processed", processedVdexCnt, pFiles.fileCnt);
  DISPLAY(l_INFO, "%u Dex files have been extracted in total", processedDexCnt);
  DISPLAY(l_INFO, "Extracted Dex files are available in '%s'",
          pRunArgs.outputDir ? pRunArgs.outputDir : dirname(pFiles.inputFile));

  exitWrapper(EXIT_SUCCESS);
}
