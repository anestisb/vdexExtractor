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

#include <getopt.h>
#include <libgen.h>
#include <sys/mman.h>

#include "common.h"
#include "log.h"
#include "utils.h"
#include "vdex_api.h"

// exit() wrapper
void exitWrapper(int errCode) {
  log_closeLogFile();
  exit(errCode);
}

// clang-format off
static void usage(bool exit_success) {
  LOGMSG_RAW(l_INFO, "              " PROG_NAME " ver. " PROG_VERSION "\n");
  LOGMSG_RAW(l_INFO, PROG_AUTHORS "\n\n");
  LOGMSG_RAW(l_INFO,"%s",
             " -i, --input=<path>   : input dir (search recursively) or single file\n"
             " -o, --output=<path>  : output path (default is same as input)\n"
             " -f, --file-override  : allow output file override if already exists (default: false)\n"
             " --no-unquicken       : disable unquicken bytecode decompiler (don't de-odex)\n"
             " --deps               : dump verified dependencies information\n"
             " --dis                : enable bytecode disassembler\n"
             " --ignore-crc-error   : decompiled Dex CRC errors are ignored (see issue #3)\n"
             " --new-crc=<path>     : text file with extracted Apk or Dex file location checksum(s)\n"
             " --get-api             : get Android API level based on Vdex version (expects single Vdex file)\n"
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
    .unquicken = true,
    .enableDisassembler = false,
    .ignoreCrc = false,
    .dumpDeps = false,
    .newCrcFile = NULL,
    .getApi = false,
  };
  infiles_t pFiles = {
    .inputFile = NULL,
    .files = NULL,
    .fileCnt = 0,
  };
  vdex_api_env_t vdex_api_env;
  vdex_api_env_t *pVdex = &vdex_api_env;

  if (argc < 1) usage(true);

  struct option longopts[] = { { "input", required_argument, 0, 'i' },
                               { "output", required_argument, 0, 'o' },
                               { "file-override", no_argument, 0, 'f' },
                               { "no-unquicken", no_argument, 0, 0x101 },
                               { "dis", no_argument, 0, 0x102 },
                               { "deps", no_argument, 0, 0x103 },
                               { "new-crc", required_argument, 0, 0x104 },
                               { "ignore-crc-error", no_argument, 0, 0x105 },
                               { "get-api", no_argument, 0, 0x106 },
                               { "debug", required_argument, 0, 'v' },
                               { "log-file", required_argument, 0, 'l' },
                               { "help", no_argument, 0, 'h' },
                               { 0, 0, 0, 0 } };

  while ((c = getopt_long(argc, argv, "i:o:fv:l:h?", longopts, NULL)) != -1) {
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
      case 0x101:
        pRunArgs.unquicken = false;
        break;
      case 0x102:
        pRunArgs.enableDisassembler = true;
        break;
      case 0x103:
        pRunArgs.dumpDeps = true;
        break;
      case 0x104:
        pRunArgs.newCrcFile = optarg;
        break;
      case 0x105:
        pRunArgs.ignoreCrc = true;
        break;
      case 0x106:
        pRunArgs.getApi = true;
        break;
      case 'v':
        logLevel = atoi(optarg);
        break;
      case 'l':
        logFile = optarg;
        break;
      case '?':
      case 'h':
        usage(true);
        break;
      default:
        exitWrapper(EXIT_FAILURE);
        break;
    }
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

  // Check output directory
  if (pRunArgs.outputDir && !utils_isValidDir(pRunArgs.outputDir)) {
    LOGMSG(l_FATAL, "'%s' output directory is not valid", pRunArgs.outputDir);
    exitWrapper(EXIT_FAILURE);
  }

  int mainRet = EXIT_FAILURE;

  if (pRunArgs.getApi) {
    if (pFiles.fileCnt != 1) {
      LOGMSG(l_ERROR, "Exactly one input Vdex file is expected when querying API level");
      goto complete;
    }

    if (!vdexApi_printApiLevel(pFiles.files[0])) {
      LOGMSG(l_ERROR, "Invalid or unsupported input Vdex file");
    } else {
      mainRet = EXIT_SUCCESS;
    }

    // We're done
    goto complete;
  }

  // Parse input file with checksums (expects one per line) and update location checksum
  if (pRunArgs.newCrcFile) {
    if (pFiles.fileCnt != 1) {
      LOGMSG(l_ERROR, "Exactly one input Vdex file is expected when updating location checksums");
      goto complete;
    }

    int nSums = -1;
    u4 *checksums = utils_processFileWithCsums(pRunArgs.newCrcFile, &nSums);
    if (checksums == NULL || nSums < 1) {
      LOGMSG(l_ERROR, "Failed to extract new location checksums from '%s'", pRunArgs.newCrcFile);
      goto complete;
    }

    if (!vdexApi_updateChecksums(pFiles.files[0], nSums, checksums, &pRunArgs)) {
      LOGMSG(l_ERROR, "Failed to update location checksums");
    } else {
      mainRet = EXIT_SUCCESS;
      DISPLAY(l_INFO, "%d location checksums have been updated", nSums);
      DISPLAY(l_INFO, "Update Vdex file is available in '%s'",
              pRunArgs.outputDir ? pRunArgs.outputDir : dirname(pFiles.inputFile));
    }

    free(checksums);
    goto complete;
  }

  size_t vdexCnt = 0, processedVdexCnt = 0, processedDexCnt = 0;
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

    // Validate Vdex magic header and initialize matching version backend
    if (!vdexApi_initEnv(buf, pVdex)) {
      LOGMSG(l_WARN, "Invalid Vdex header - skipping '%s'", pFiles.files[f]);
      goto next_file;
    }

    pVdex->dumpHeaderInfo(buf);
    vdexCnt++;

    // Dump Vdex verified dependencies info
    if (pRunArgs.dumpDeps) {
      log_setDisStatus(true);  // TODO: Remove
      // TODO: Migrate this to vdex_process to avoid iterating Dex files twice. For now it's not
      // a priority since the two flags offer different functionalities thus no point using them
      // at the same time.
      pVdex->dumpDepsInfo(buf);
      log_setDisStatus(false);
    }

    if (pRunArgs.enableDisassembler) {
      log_setDisStatus(true);
    }

    // Unquicken Dex bytecode or simply walk optimized Dex files
    int ret = pVdex->process(pFiles.files[f], buf, (size_t)fileSz, &pRunArgs);
    if (ret == -1) {
      LOGMSG(l_ERROR, "Failed to process Dex files - skipping '%s'", pFiles.files[f]);
      goto next_file;
    }

    processedDexCnt += ret;
    processedVdexCnt++;

  next_file:
    // Clean-up
    munmap(buf, fileSz);
    close(srcfd);
  }

  DISPLAY(l_INFO, "%zu out of %u Vdex files have been processed", processedVdexCnt, vdexCnt);
  DISPLAY(l_INFO, "%u Dex files have been extracted in total", processedDexCnt);
  DISPLAY(l_INFO, "Extracted Dex files are available in '%s'",
          pRunArgs.outputDir ? pRunArgs.outputDir
                             : (utils_isValidDir(pFiles.inputFile) ? pFiles.inputFile
                                                                   : dirname(pFiles.inputFile)));
  mainRet = EXIT_SUCCESS;

complete:
  if (pFiles.fileCnt > 1) {
    for (size_t i = 0; i < pFiles.fileCnt; i++) {
      free(pFiles.files[i]);
    }
  }
  free(pFiles.files);
  exitWrapper(mainRet);
}
