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

#include "out_writer.h"

#include "dex.h"
#include "utils.h"

void outWriter_formatName(char *outBuf,
                          size_t outBufLen,
                          const char *rootPath,
                          const char *fName,
                          size_t classId,
                          const char *suffix) {
  // Trim Vdex extension and replace with Apk
  const char *fileExt = strrchr(fName, '.');
  int fNameLen = strlen(fName);
  if (fileExt) {
    fNameLen = fileExt - fName;
  }
  char formattedName[PATH_MAX] = { 0 };
  if (classId == 0) {
    snprintf(formattedName, sizeof(formattedName), "%.*s_classes.%s", fNameLen, fName, suffix);
  } else {
    snprintf(formattedName, sizeof(formattedName), "%.*s_classes%zu.%s", fNameLen, fName,
             classId + 1, suffix);
  }

  if (rootPath == NULL) {
    // Save to same directory as input file
    snprintf(outBuf, outBufLen, "%s", formattedName);
  } else {
    const char *pFileBaseName = utils_fileBasename(formattedName);
    snprintf(outBuf, outBufLen, "%s/%s", rootPath, pFileBaseName);
    free((void *)pFileBaseName);
  }
}

bool outWriter_DexFile(const runArgs_t *pRunArgs,
                       const char *VdexFileName,
                       size_t dexIdx,
                       const u1 *buf,
                       size_t bufSize) {
  char outFile[PATH_MAX] = { 0 };
  outWriter_formatName(outFile, sizeof(outFile), pRunArgs->outputDir, VdexFileName, dexIdx,
                       dex_checkType(buf) == kNormalDex ? "dex" : "cdex");

  // Write Dex file
  int fileFlags = O_CREAT | O_RDWR;
  if (pRunArgs->fileOverride == false) {
    fileFlags |= O_EXCL;
  }
  int dstfd = -1;
  dstfd = open(outFile, fileFlags, 0644);
  if (dstfd == -1) {
    LOGMSG_P(l_ERROR, "Couldn't create output file '%s' - skipping 'classes%zu.dex'", outFile,
             dexIdx);
    return false;
  }

  if (!utils_writeToFd(dstfd, buf, bufSize)) {
    close(dstfd);
    LOGMSG(l_ERROR, "Couldn't write '%s' file - skipping 'classes%zu.dex'", outFile, dexIdx);
    return false;
  }

  close(dstfd);
  return true;
}

bool outWriter_VdexFile(const runArgs_t *pRunArgs, const char *VdexFileName, u1 *buf, off_t bufSz) {
  const char *fileExt = strrchr(VdexFileName, '.');
  int fNameLen = strlen(VdexFileName);
  if (fileExt) {
    fNameLen = fileExt - VdexFileName;
  }
  char outFileName[PATH_MAX] = { 0 };
  if (pRunArgs->outputDir == NULL) {
    snprintf(outFileName, sizeof(outFileName), "%.*s_updated.vdex", fNameLen, VdexFileName);
  } else {
    const char *pFileBaseName = utils_fileBasename(VdexFileName);
    snprintf(outFileName, sizeof(outFileName), "%s/%s_updated.vdex", pRunArgs->outputDir,
             pFileBaseName);
    free((void *)pFileBaseName);
  }

  int dstfd = -1;
  dstfd = open(outFileName, O_CREAT | O_RDWR, 0644);
  if (dstfd == -1) {
    LOGMSG_P(l_ERROR, "Couldn't create output file '%s'", outFileName);
    return false;
  }

  if (!utils_writeToFd(dstfd, buf, bufSz)) {
    close(dstfd);
    LOGMSG(l_ERROR, "Couldn't write '%s' file", outFileName);
    return false;
  }

  close(dstfd);
  return true;
}
