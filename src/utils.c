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

#include <dirent.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "utils.h"

static bool utils_readdir(infiles_t *pFiles) {
  DIR *dir = opendir(pFiles->inputFile);
  if (!dir) {
    LOGMSG_P(l_ERROR, "Couldn't open dir '%s'", pFiles->inputFile);
    return false;
  }

  size_t count = 0;
  for (;;) {
    errno = 0;
    struct dirent *entry = readdir(dir);
    if (entry == NULL && errno == EINTR) {
      continue;
    }
    if (entry == NULL && errno != 0) {
      LOGMSG_P(l_ERROR, "readdir('%s')", pFiles->inputFile);
      return false;
    }
    if (entry == NULL) {
      break;
    }

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", pFiles->inputFile, entry->d_name);

    struct stat st;
    if (stat(path, &st) == -1) {
      LOGMSG(l_WARN, "Couldn't stat() the '%s' file", path);
      continue;
    }

    if (!S_ISREG(st.st_mode)) {
      LOGMSG(l_DEBUG, "'%s' is not a regular file, skipping", path);
      continue;
    }

    if (st.st_size == 0) {
      LOGMSG(l_DEBUG, "'%s' is empty", path);
      continue;
    }

    if (!(pFiles->files = realloc(pFiles->files, sizeof(char *) * (count + 1)))) {
      LOGMSG_P(l_ERROR, "Couldn't allocate memory");
      closedir(dir);
      return false;
    }

    pFiles->files[count] = strdup(path);
    if (!pFiles->files[count]) {
      LOGMSG_P(l_ERROR, "Couldn't allocate memory");
      closedir(dir);
      return false;
    }
    pFiles->fileCnt = ++count;

    LOGMSG(l_DEBUG, "Added '%s' to the list of input files", path);
  }

  closedir(dir);
  if (count == 0) {
    LOGMSG(l_ERROR, "Directory '%s' doesn't contain any regular files", pFiles->inputFile);
    return false;
  }

  LOGMSG(l_INFO, "%u input files have been added to the list", pFiles->fileCnt);
  return true;
}

bool utils_init(infiles_t *pFiles) {
  pFiles->files = malloc(sizeof(char *));
  if (!pFiles->files) {
    LOGMSG_P(l_ERROR, "Couldn't allocate memory");
    return false;
  }

  if (!pFiles->inputFile) {
    LOGMSG(l_ERROR, "No input file/dir specified");
    return false;
  }

  struct stat st;
  if (stat(pFiles->inputFile, &st) == -1) {
    LOGMSG_P(l_ERROR, "Couldn't stat the input file/dir '%s'", pFiles->inputFile);
    return false;
  }

  if (S_ISDIR(st.st_mode)) {
    return utils_readdir(pFiles);
  }

  if (!S_ISREG(st.st_mode)) {
    LOGMSG(l_ERROR, "'%s' is not a regular file, nor a directory", pFiles->inputFile);
    return false;
  }

  pFiles->files[0] = pFiles->inputFile;
  pFiles->fileCnt = 1;

  return true;
}

bool utils_writeToFd(int fd, const uint8_t *buf, off_t fileSz) {
  off_t written = 0;
  while (written < fileSz) {
    ssize_t sz = write(fd, &buf[written], fileSz - written);
    if (sz < 0 && errno == EINTR) continue;

    if (sz < 0) return false;

    written += sz;
  }

  return true;
}

uint8_t *utils_mapFileToRead(char *fileName, off_t *fileSz, int *fd) {
  if ((*fd = open(fileName, O_RDONLY)) == -1) {
    LOGMSG_P(l_WARN, "Couldn't open() '%s' file in R/O mode", fileName);
    return NULL;
  }

  struct stat st;
  if (fstat(*fd, &st) == -1) {
    LOGMSG_P(l_WARN, "Couldn't stat() the '%s' file", fileName);
    close(*fd);
    return NULL;
  }

  uint8_t *buf;
  if ((buf = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, *fd, 0)) == MAP_FAILED) {
    LOGMSG_P(l_WARN, "Couldn't mmap() the '%s' file", fileName);
    close(*fd);
    return NULL;
  }

  *fileSz = st.st_size;
  return buf;
}

void utils_hexDump(char *desc, const uint8_t *addr, int len) {
  int i;
  unsigned char buff[17];
  unsigned char *pc = (unsigned char *)addr;

  // Output description if given.
  if (desc != NULL) LOGMSG_RAW(l_DEBUG, "%s:\n", desc);

  if (len == 0) {
    LOGMSG_RAW(l_DEBUG, "  ZERO LENGTH\n");
    return;
  }
  if (len < 0) {
    LOGMSG_RAW(l_DEBUG, "  NEGATIVE LENGTH: %i\n", len);
    return;
  }

  // Process every byte in the data.
  for (i = 0; i < len; i++) {
    // Multiple of 16 means new line (with line offset).

    if ((i % 16) == 0) {
      // Just don't print ASCII for the zeroth line.
      if (i != 0) LOGMSG_RAW(l_DEBUG, "  %s\n", buff);

      // Output the offset.
      LOGMSG_RAW(l_DEBUG, "  %04x ", i);
    }

    // Now the hex code for the specific character.
    LOGMSG_RAW(l_DEBUG, " %02x", pc[i]);

    // And store a printable ASCII character for later.
    if ((pc[i] < 0x20) || (pc[i] > 0x7e))
      buff[i % 16] = '.';
    else
      buff[i % 16] = pc[i];
    buff[(i % 16) + 1] = '\0';
  }

  // Pad out last line if not exactly 16 characters.
  while ((i % 16) != 0) {
    LOGMSG_RAW(l_DEBUG, "   ");
    i++;
  }

  // And print the final ASCII bit.
  LOGMSG_RAW(l_DEBUG, "  %s\n", buff);
}

char *utils_bin2hex(const unsigned char *str, const size_t strLen) {
  char *result = (char *)malloc(strLen * 2 + 1);
  size_t i, j;
  int b = 0;

  for (i = j = 0; i < strLen; i++) {
    b = str[i] >> 4;
    result[j++] = (char)(87 + b + (((b - 10) >> 31) & -39));
    b = str[i] & 0xf;
    result[j++] = (char)(87 + b + (((b - 10) >> 31) & -39));
  }
  result[j] = '\0';
  return result;
}

void *utils_malloc(size_t sz) {
  void *p = malloc(sz);
  if (p == NULL) {
    // This is expected to abort
    LOGMSG(l_FATAL, "malloc(size='%zu')", sz);
  }
  return p;
}

void *utils_calloc(size_t sz) {
  void *p = utils_malloc(sz);
  memset(p, '\0', sz);
  return p;
}

void *utils_realloc(void *ptr, size_t sz) {
  void *ret = realloc(ptr, sz);
  if (ret == NULL) {
    // This is expected to abort
    LOGMSG_P(l_FATAL, "realloc(%p, %zu)", ptr, sz);
    free(ptr);
  }
  return ret;
}

void *utils_crealloc(void *ptr, size_t old_sz, size_t new_sz) {
  // utils_realloc is expected to abort in case of error
  void *ret = utils_realloc(ptr, new_sz);
  memset(ret + old_sz, 0, new_sz - old_sz);
  return ret;
}

void utils_pseudoStrAppend(const char **charBuf,
                           size_t *charBufSz,
                           size_t *charBufOff,
                           const char *strToAppend) {
  const char *buf = *charBuf;

  const size_t kResizeChunk = 512;
  if (*charBufSz == 1) {
    LOGMSG(l_FATAL, "Pseudo string buffer size must be > 1");
  }

  // If charBuf is null, allocate a new buffer
  if (buf == NULL) {
    size_t alocSize = (*charBufSz == 0) ? kResizeChunk : *charBufSz;
    buf = utils_calloc(alocSize);
    *charBufSz = alocSize;
    *charBufOff = 0;
  }

  // Always ensure null termination
  size_t actualBufSz = *charBufSz - 1;

  // Verify valid offset is provided
  if (*charBufOff > actualBufSz) {
    LOGMSG(l_FATAL, "Invalid string buffer offset (%zu)", *charBufOff);
  }

  // Check if new string can fit
  if (strlen(strToAppend) + *charBufOff > actualBufSz) {
    // We need to resize. utils_crealloc is expected to abort in case of error
    size_t resizeSize = *charBufSz + kResizeChunk;
    while (resizeSize <= strlen(strToAppend) + *charBufOff) {
      resizeSize += kResizeChunk;
    }
    buf = utils_crealloc((void *)buf, *charBufSz, *charBufSz + resizeSize);
    *charBufSz += resizeSize;
    actualBufSz += resizeSize;
  }

  // Then append the actual string
  strncpy((void *)(buf + *charBufOff), strToAppend, strlen(strToAppend));
  *charBufOff += strlen(strToAppend);

  // Update reference before returning
  *charBuf = buf;
}
