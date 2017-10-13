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

#include <fcntl.h>
#include <getopt.h>
#include <libgen.h>
#include <sys/mman.h>

#include "common.h"
#include "log.h"
#include "utils.h"
#include "vdex.h"

/* Module global variables */
static int logLevel = l_INFO;

/* Help page */
static void usage(bool exit_success) {
  printf("%s", "  " AB "-i,  --input=<path>" AC
               "  : input dir (1 max depth) or single file\n"
               "  " AB "-o,  --output=<path>" AC
               " : output path (default is same as input)\n"
               "  " AB "-u,  --unquicken" AC
               "     : unquicken bytecode (under development)\n"
               "  " AB "-h,  --help" AC
               "          : this help\n"
               "  " AB "-v,  --debug=LEVEL" AC
               "   : "
               "debug level (0 - FATAL ... 5 - VDEBUG), default: '" AB "3" AC
               "' (INFO)\n");

  if (exit_success)
    exit(EXIT_SUCCESS);
  else
    exit(EXIT_FAILURE);
}

static char *fileBasename(char const *path) {
  char *s = strrchr(path, '/');
  if (!s) {
    return strdup(path);
  } else {
    return strdup(s + 1);
  }
}

static void formatName(char *outBuf,
                       size_t outBufLen,
                       char *rootPath,
                       char *fName,
                       size_t classId) {
  char formattedName[PATH_MAX] = { 0 };
  if (classId == 0) {
    snprintf(formattedName, sizeof(formattedName), "%s_classes.dex", fName);
  } else {
    snprintf(formattedName, sizeof(formattedName), "%s_classes%zu.dex", fName,
             classId);
  }

  if (rootPath == NULL) {
    /* Save to same directory as input file */
    snprintf(outBuf, outBufLen, "%s", formattedName);
  } else {
    snprintf(outBuf, outBufLen, "%s/%s", rootPath, fileBasename(formattedName));
  }
}

int main(int argc, char **argv) {
  int c;
  char *outputDir = NULL;
  bool unquicken = false;

  /* Default values */
  infiles_t pFiles = {
    .inputFile = NULL, .files = NULL, .fileCnt = 0,
  };

  printf("\t\t" AB PROG_NAME " ver. " PROG_VERSION "\n\n" PROG_AUTHORS AC
         "\n\n");
  if (argc < 1) usage(true);

  struct option longopts[] = { { "input", required_argument, 0, 'i' },
                               { "output", required_argument, 0, 'o' },
                               { "unquicken", no_argument, 0, 'u' },
                               { "help", no_argument, 0, 'h' },
                               { "debug", required_argument, 0, 'v' },
                               { 0, 0, 0, 0 } };

  while ((c = getopt_long(argc, argv, "i:o:uhv:", longopts, NULL)) != -1) {
    switch (c) {
      case 'i':
        pFiles.inputFile = optarg;
        break;
      case 'o':
        outputDir = optarg;
        break;
      case 'u':
        unquicken = true;
        break;
      case 'h':
        usage(true);
        break;
      case 'v':
        logLevel = atoi(optarg);
        break;
      default:
        break;
    }
  }

  /* adjust log level */
  log_setMinLevel(logLevel);

  /* initialize input files */
  if (!utils_init(&pFiles)) {
    LOGMSG(l_FATAL, "Couldn't load input files");
    exit(EXIT_FAILURE);
  }

  size_t processedVdexCnt = 0, processedDexCnt = 0;

  for (size_t f = 0; f < pFiles.fileCnt; f++) {
    off_t fileSz = 0;
    int srcfd = -1;
    uint8_t *buf = NULL;

    LOGMSG(l_DEBUG, "Processing '%s'", pFiles.files[f]);

    /* mmap file */
    buf = utils_mapFileToRead(pFiles.files[f], &fileSz, &srcfd);
    if (buf == NULL) {
      LOGMSG(l_ERROR, "open & map failed for R/O mode. Skipping '%s'",
             pFiles.files[f]);
      continue;
    }

    if ((size_t)fileSz < (sizeof(vdexHeader) + sizeof(dexHeader))) {
      LOGMSG(l_WARN, "Invalid input file - skipping '%s'", pFiles.files[f]);
      munmap(buf, fileSz);
      close(srcfd);
      continue;
    }

    const vdexHeader *pVdexHeader = (const vdexHeader *)buf;

    /* Validate VDEX magic header */
    if (!vdex_isValidVdex(buf)) {
      LOGMSG(l_WARN, "Invalid vdex header - skipping '%s'", pFiles.files[f]);
      munmap(buf, fileSz);
      close(srcfd);
      continue;
    }

    if (unquicken) {
      LOGMSG(l_WARN, "Vdex unquickening backend is under development");
      // if(vdex_Unquicken(buf) == false) {
      //   LOGMSG(l_ERROR, "Failed to unquicken dex files - skipping '%s'",
      //          pFiles.files[f]);
      //   munmap(buf, fileSz);
      //   close(srcfd);
      //   continue;
      // }
    }

    const uint8_t *current_data = NULL;
    uint32_t offset = 0;
    for (size_t i = 0; i < pVdexHeader->number_of_dex_files_; ++i) {
      current_data = vdex_GetNextDexFileData(buf, &offset);
      if (current_data == NULL) {
        LOGMSG(l_ERROR, "Failed to extract 'classes%zu.dex' - skipping", i);
        continue;
      }
      dexHeader *pDexHeader = (dexHeader *)current_data;

      /* If unquicken DEX files have already been verified */
      if (unquicken == false && dex_isValidDexMagic(pDexHeader) == false) {
        LOGMSG(l_ERROR, "Invalid dex file'classes%zu.dex' - skipping", i);
        continue;
      }

      /* Repair CRC */
      dex_repairDexCRC(current_data, pDexHeader->fileSize);

      char outFile[PATH_MAX] = { 0 };
      formatName(outFile, sizeof(outFile), outputDir, pFiles.files[f], i);

      /* Write DEX file */
      int dstfd = -1;
      dstfd = open(outFile, O_CREAT | O_EXCL | O_RDWR, 0644);
      if (dstfd == -1) {
        LOGMSG_P(l_ERROR, "Couldn't create output file '%s' in input directory",
                 outFile);
        LOGMSG(l_WARN, "Skipping 'classes%zu.dex'", i);
        continue;
      }

      if (!utils_writeToFd(dstfd, current_data, pDexHeader->fileSize)) {
        close(dstfd);
        LOGMSG(l_WARN, "Skipping 'classes%zu.dex'", i);
        continue;
      }

      processedDexCnt++;
      close(dstfd);
    }

    processedVdexCnt++;

    /* Clean-up */
    munmap(buf, fileSz);
    buf = NULL;
    close(srcfd);
  }

  LOGMSG(l_INFO, "%u out of %u VDEX files have been processed",
         processedVdexCnt, pFiles.fileCnt);
  LOGMSG(l_INFO, "%u DEX files have been extracted in total", processedDexCnt);
  LOGMSG(l_INFO, "Extracted DEX files available in '%s'",
         outputDir ? outputDir : dirname(pFiles.inputFile));

  return EXIT_SUCCESS;
}
