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

#include "vdex_api.h"

#include <sys/mman.h>

#include "log.h"
#include "out_writer.h"
#include "utils.h"
#include "vdex/vdex_006.h"
#include "vdex/vdex_010.h"
#include "vdex/vdex_019.h"
#include "vdex/vdex_021.h"

bool vdexApi_initEnv(const u1 *cursor, vdex_api_env_t *env) {
  // Check if a supported Vdex version is found
  if (vdex_006_isValidVdex(cursor)) {
    LOGMSG(l_DEBUG, "Initializing environment for Vdex version '006'");
    env->dumpHeaderInfo = vdex_006_dumpHeaderInfo;
    env->dumpDepsInfo = vdex_006_dumpDepsInfo;
    env->process = vdex_006_process;
  } else if (vdex_010_isValidVdex(cursor)) {
    LOGMSG(l_DEBUG, "Initializing environment for Vdex version '010'");
    env->dumpHeaderInfo = vdex_010_dumpHeaderInfo;
    env->dumpDepsInfo = vdex_010_dumpDepsInfo;
    env->process = vdex_010_process;
  } else if (vdex_019_isValidVdex(cursor)) {
    LOGMSG(l_DEBUG, "Initializing environment for Vdex version '019'");
    env->dumpHeaderInfo = vdex_019_dumpHeaderInfo;
    env->dumpDepsInfo = vdex_019_dumpDepsInfo;
    env->process = vdex_019_process;
  } else if (vdex_021_isValidVdex(cursor)) {
    LOGMSG(l_DEBUG, "Initializing environment for Vdex version '021'");
    env->dumpHeaderInfo = vdex_021_dumpHeaderInfo;
    env->dumpDepsInfo = vdex_021_dumpDepsInfo;
    env->process = vdex_021_process;
  } else {
    LOGMSG(l_ERROR, "Unsupported Vdex version");
    return false;
  }

  return true;
}

bool vdexApi_updateChecksums(const char *inVdexFileName,
                             int nCsums,
                             u4 *checksums,
                             const runArgs_t *pRunArgs) {
  bool ret = false;
  off_t fileSz = 0;
  int srcfd = -1;
  u1 *buf = NULL;

  buf = utils_mapFileToRead(inVdexFileName, &fileSz, &srcfd);
  if (buf == NULL) {
    LOGMSG(l_ERROR, "'%s' open & map failed", inVdexFileName);
    return ret;
  }

  if (vdex_006_isValidVdex(buf)) {
    const vdexHeader_006 *pVdexHeader = (const vdexHeader_006 *)buf;
    if ((u4)nCsums != pVdexHeader->numberOfDexFiles) {
      LOGMSG(l_ERROR, "%d checksums loaded from file, although Vdex has %" PRIu32 " Dex entries",
             nCsums, pVdexHeader->numberOfDexFiles)
      goto fini;
    }

    for (u4 i = 0; i < pVdexHeader->numberOfDexFiles; ++i) {
      vdex_006_SetLocationChecksum(buf, i, checksums[i]);
    }
  } else if (vdex_010_isValidVdex(buf)) {
    const vdexHeader_010 *pVdexHeader = (const vdexHeader_010 *)buf;
    if ((u4)nCsums != pVdexHeader->numberOfDexFiles) {
      LOGMSG(l_ERROR, "%d checksums loaded from file, although Vdex has %" PRIu32 " Dex entries",
             nCsums, pVdexHeader->numberOfDexFiles)
      goto fini;
    }

    for (u4 i = 0; i < pVdexHeader->numberOfDexFiles; ++i) {
      vdex_010_SetLocationChecksum(buf, i, checksums[i]);
    }
  } else {
    LOGMSG(l_ERROR, "Unsupported Vdex version - updateChecksums failed");
    goto fini;
  }

  if (!outWriter_VdexFile(pRunArgs, inVdexFileName, buf, fileSz)) {
    LOGMSG(l_ERROR, "Failed to write updated Vdex file");
    goto fini;
  }

  ret = true;

fini:
  munmap(buf, fileSz);
  close(srcfd);
  return ret;
}

bool vdexApi_printApiLevel(const char *inVdexFileName) {
  bool ret = false;
  off_t fileSz = 0;
  int srcfd = -1;
  u1 *buf = NULL;

  buf = utils_mapFileToRead(inVdexFileName, &fileSz, &srcfd);
  if (buf == NULL) {
    LOGMSG(l_ERROR, "'%s' open & map failed", inVdexFileName);
    return ret;
  }

  if (vdex_006_isValidVdex(buf)) {
    log_raw("API-26\n");
  } else if (vdex_010_isValidVdex(buf)) {
    log_raw("API-27\n");
  } else if (vdex_019_isValidVdex(buf)) {
    log_raw("API-28\n");
  } else if (vdex_021_isValidVdex(buf)) {
    log_raw("API-29\n");
  } else {
    goto fini;
  }

  ret = true;

fini:
  munmap(buf, fileSz);
  close(srcfd);
  return ret;
}
