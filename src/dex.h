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

#ifndef _DEX_H_
#define _DEX_H_

#include <zlib.h>
#include "common.h"
#include "dex_instruction.h"

#define kNumDexVersions 4
#define kDexVersionLen 4
#define kSHA1Len 20

static const uint8_t kDexMagic[] = { 'd', 'e', 'x', '\n' };
static const uint8_t kDexMagicVersions[kNumDexVersions][kDexVersionLen] = {
  { '0', '3', '5', '\0' },
  // Dex version 036 skipped
  { '0', '3', '7', '\0' },
  // Dex version 038: Android "O".
  { '0', '3', '8', '\0' },
  // Dex verion 039: Beyond Android "O".
  { '0', '3', '9', '\0' },
};

typedef struct __attribute__((packed)) {
  char dex[3];
  char nl[1];
  char ver[3];
  char zero[1];
} dexMagic;

typedef struct __attribute__((packed)) {
  dexMagic magic;
  u4 checksum;
  unsigned char signature[kSHA1Len];
  u4 fileSize;
  u4 headerSize;
  u4 endianTag;
  u4 linkSize;
  u4 linkOff;
  u4 mapOff;
  u4 stringIdsSize;
  u4 stringIdsOff;
  u4 typeIdsSize;
  u4 typeIdsOff;
  u4 protoIdsSize;
  u4 protoIdsOff;
  u4 fieldIdsSize;
  u4 fieldIdsOff;
  u4 methodIdsSize;
  u4 methodIdsOff;
  u4 classDefsSize;
  u4 classDefsOff;
  u4 dataSize;
  u4 dataOff;
} dexHeader;

typedef struct __attribute__((packed)) { u4 stringDataOff; } dexStringId;

typedef struct __attribute__((packed)) { u4 descriptorIdx; } dexTypeId;

typedef struct __attribute__((packed)) {
  u2 classIdx;
  u2 typeIdx;
  u4 nameIdx;
} dexFieldId;

typedef struct __attribute__((packed)) {
  u2 classIdx;
  u2 protoIdx;
  u4 nameIdx;
} dexMethodId;

typedef struct __attribute__((packed)) {
  u4 shortyIdx;
  u4 returnTypeIdx;
  u4 parametersOff;
} dexProtoId;

typedef struct __attribute__((packed)) {
  u4 classIdx;
  u4 accessFlags;
  u4 superclassOdx;
  u4 interfacesOff;
  u4 sourceFileIdx;
  u4 annotationsOff;
  u4 classDataOff;
  u4 staticValuesOff;
} dexClassDef;

typedef struct __attribute__((packed)) { u2 typeIdx; } dexTypeItem;

typedef struct __attribute__((packed)) {
  u4 size;
  dexTypeItem list[1];
} dexTypeList;

typedef struct __attribute__((packed)) {
  u2 type;
  u2 unused;
  u4 size;
  u4 offset;
} dexMapItem;

typedef struct __attribute__((packed)) {
  u4 size;
  dexMapItem list[1];
} dexMapList;

typedef struct __attribute__((packed)) {
  u2 registersSize;
  u2 insSize;
  u2 outsSize;
  u2 tries_size;
  u4 debug_info_off;
  u4 insns_size;
  u2 insns[1];
  // followed by optional u2 padding
  // followed by try_item[triesSize]
  // followed by uleb128 handlersSize
  // followed by catch_handler_item[handlersSize]
} dexCode;

typedef struct __attribute__((packed)) {
  u4 start_addr_;
  u2 insn_count_;
  u2 handler_off_;
} dexTryItem;

typedef struct __attribute__((packed)) { u1 bleargh; } dexLinkData;

typedef struct __attribute__((packed)) {
  int size;
  int numEntries;
  struct {
    u4 classDescriptorHash;
    int classDescriptorOff;
    int classDefOff;
  } table[1];
} dexClassLookup;

typedef struct __attribute__((packed)) {
  u4 staticFieldsSize;
  u4 instanceFieldsSize;
  u4 directMethodsSize;
  u4 virtualMethodsSize;
} dexClassDataHeader;

typedef struct __attribute__((packed)) {
  u4 methodIdx;
  u4 accessFlags;
  u4 codeOff;
} dexMethod;

typedef struct __attribute__((packed)) {
  u4 fieldIdx;
  u4 accessFlags;
} dexField;

typedef enum {
  kDexAccessForClass = 0,
  kDexAccessForMethod = 1,
  kDexAccessForField = 2,
  kDexAccessForMAX
} dexAccessFor;
#define kDexNumAccessFlags 18

// Verify if valid Dex file magic number
bool dex_isValidDexMagic(const dexHeader *);

// Debug print Dex header info
void dex_dumpHeaderInfo(const dexHeader *);

// Compute Dex file CRC
uint32_t dex_computeDexCRC(const uint8_t *, off_t);

// Repair Dex file CRC
void dex_repairDexCRC(const uint8_t *, off_t);

// Reads an unsigned LEB128 (Little-Endian Base 128) value, updating the
// given pointer to point just past the end of the read value. This function
// tolerates non-zero high-order bits in the fifth encoded byte.
uint32_t dex_readULeb128(const u1 **);

// Reads a signed LEB128 value, updating the given pointer to point
// just past the end of the read value. This function tolerates
// non-zero high-order bits in the fifth encoded byte.
int32_t dex_readSLeb128(const uint8_t **);

// Get the offset of the first instruction for a given dexMethod
uint32_t dex_getFirstInstrOff(const dexMethod *);

// Read Leb128 class data header
void dex_readClassDataHeader(const uint8_t **, dexClassDataHeader *);

// Read a Leb128 class data field item
void dex_readClassDataField(const uint8_t **, dexField *);

// Read a Leb128 class data method item
void dex_readClassDataMethod(const uint8_t **, dexMethod *);

// Methods to access Dex file primitive types
const dexStringId *dex_getStringId(const u1 *, u2);
const dexTypeId *dex_getTypeId(const u1 *, u2);
const dexProtoId *dex_getProtoId(const u1 *, u2);
const dexFieldId *dex_getFieldId(const u1 *, u4);
const dexMethodId *dex_getMethodId(const u1 *, u4);
const dexClassDef *dex_getClassDef(const u1 *, u2);

// Helper methods to extract data from Dex primitive types
const char *dex_getStringDataAndUtf16Length(const u1 *, const dexStringId *, u4 *);
const char *dex_getStringDataAndUtf16LengthByIdx(const u1 *, u2, u4 *);
const char *dex_getStringDataByIdx(const u1 *, u2);
const char *dex_getStringByTypeIdx(const u1 *, u2);
const char *dex_getMethodSignature(const u1 *, const dexMethodId *);
const char *dex_getProtoSignature(const u1 *, const dexProtoId *);
const dexTypeList *dex_getProtoParameters(const u1 *, const dexProtoId *);

// Functions to print information of primitive types (mainly used by disassembler)
void dex_dumpClassInfo(const u1 *, u4);
void dex_dumpMethodInfo(const u1 *, dexMethod *, u4, const char *);
void dex_dumpInstruction(const u1 *, u2 *, u4, u4, bool);

// Converts a type descriptor to human-readable "dotted" form.  For
// example, "Ljava/lang/String;" becomes "java.lang.String", and
// "[I" becomes "int[]".  Also converts '$' to '.', which means this
// form can't be converted back to a descriptor.
char *dex_descriptorToDot(const char *);

// Converts the class name portion of a type descriptor to human-readable
// "dotted" form. For example, "Ljava/lang/String;" becomes "String".
char *dex_descriptorClassToDot(const char *);

#endif
