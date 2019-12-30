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

#ifndef _DEX_H_
#define _DEX_H_

#include <zlib.h>

#include "common.h"
#include "dex_instruction.h"
#include "dex_modifiers.h"

// CompactDex helper constants for CodeItem decoding
#define kRegistersSizeShift ((size_t)12)
#define kInsSizeShift ((size_t)8)
#define kOutsSizeShift ((size_t)4)
#define kTriesSizeSizeShift ((size_t)0)
#define kFlagPreHeaderRegisterSize ((u2)(0x1 << 0))
#define kFlagPreHeaderInsSize ((u2)(0x1 << 1))
#define kFlagPreHeaderOutsSize ((u2)(0x1 << 2))
#define kFlagPreHeaderTriesSize ((u2)(0x1 << 3))
#define kFlagPreHeaderInsnsSize ((u2)(0x1 << 4))
#define kInsnsSizeShift ((size_t)5)
#define kBitsPerByte ((size_t)8)
// #define kInsnsSizeBits ((size_t)(sizeof(u2) * kBitsPerByte -  kInsnsSizeShift))
#define kFlagPreHeaderCombined                                                        \
  ((u2)(kFlagPreHeaderRegisterSize | kFlagPreHeaderInsSize | kFlagPreHeaderOutsSize | \
        kFlagPreHeaderTriesSize | kFlagPreHeaderInsnsSize))

#define kBitsPerIntPtrT ((int)(sizeof(intptr_t) * kBitsPerByte))

#define kNumDexVersions 4
#define kNumCDexVersions 1
#define kDexVersionLen 4
#define kSHA1Len 20

static const uint16_t kDexNoIndex16 = 0xFFFF;

static const u1 kDexMagic[] = { 'd', 'e', 'x', '\n' };
static const u1 kDexMagicVersions[kNumDexVersions][kDexVersionLen] = {
  { '0', '3', '5', '\0' },
  // Dex version 036 skipped
  { '0', '3', '7', '\0' },
  // Dex version 038: Android "O".
  { '0', '3', '8', '\0' },
  // Dex version 039: Beyond Android "O".
  { '0', '3', '9', '\0' },
};

static const u1 kCDexMagic[] = { 'c', 'd', 'e', 'x' };
static const u1 kCDexMagicVersions[kNumCDexVersions][kDexVersionLen] = {
  // Android "P" and above
  { '0', '0', '1', '\0' },
};

typedef enum { kDexInvalid = 0, kNormalDex = 1, kCompactDex = 2 } dexType;

typedef struct __attribute__((packed)) {
  char dex[4];
  char ver[4];
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
  u4 featureFlags;
  u4 debugInfoOffsetsPos;
  u4 debugInfoOffsetsTableOffset;
  u4 debugInfoBase;
  u4 ownedDataBegin;
  u4 ownedDataEnd;
} cdexHeader;

typedef struct __attribute__((packed)) {
  u4 stringDataOff;
} dexStringId;

typedef struct __attribute__((packed)) {
  u4 descriptorIdx;
} dexTypeId;

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

typedef struct __attribute__((packed)) {
  u2 typeIdx;
} dexTypeItem;

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

typedef struct __attribute__((packed, aligned(4))) {
  // the number of registers used by this code (locals + parameters)
  u2 registersSize;
  // the number of words of incoming arguments to the method  that this code is for
  u2 insSize;
  // the number of words of outgoing argument space required by this code for method invocation
  u2 outsSize;
  // the number of try_items for this instance. If non-zero, then these appear as the tries array
  // just after the insns in this instance.
  u2 triesSize;
  // Holds file offset to debug info stream.
  u4 debugInfoOff;
  // size of the insns array, in 2 byte code units
  u4 insnsSize;
  // actual array of bytecode
  u2 insns[1];
  // followed by optional u2 padding
  // followed by try_item[triesSize]
  // followed by uleb128 handlersSize
  // followed by catch_handler_item[handlersSize]
} dexCode;

typedef struct __attribute__((packed, aligned(2))) {
  // Packed code item data, 4 bits each: [registers_size, ins_size, outs_size, tries_size]
  u2 fields;
  // 5 bits for if either of the fields required preheader extension, 11 bits for the number of
  // instruction code units.
  u2 insnsCountAndFlags;
  u2 insns[1];
  // followed by optional u2 padding
  // followed by try_item[triesSize]
  // followed by uleb128 handlersSize
  // followed by catch_handler_item[handlersSize]
} cdexCode;

typedef struct __attribute__((packed)) {
  u4 start_addr_;
  u2 insn_count_;
  u2 handler_off_;
} dexTryItem;

typedef struct __attribute__((packed)) {
  u1 bleargh;
} dexLinkData;

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

// Return type of Dex file based on magic number
dexType dex_checkType(const u1 *);

// Verify if valid Dex file magic number
bool dex_isValidDex(const u1 *);

// Verify if valid CompactDex file magic number
bool dex_isValidCDex(const u1 *);

// Debug print Dex header info
void dex_dumpHeaderInfo(const u1 *);

// Access header data
dexMagic dex_getMagic(const u1 *);
u4 dex_getChecksum(const u1 *);
u4 dex_getFileSize(const u1 *);
u4 dex_getHeaderSize(const u1 *);
u4 dex_getEndianTag(const u1 *);
u4 dex_getLinkSize(const u1 *);
u4 dex_getLinkOff(const u1 *);
u4 dex_getMapOff(const u1 *);
u4 dex_getStringIdsSize(const u1 *);
u4 dex_getStringIdsOff(const u1 *);
u4 dex_getTypeIdsSize(const u1 *);
u4 dex_getTypeIdsOff(const u1 *);
u4 dex_getProtoIdsSize(const u1 *);
u4 dex_getProtoIdsOff(const u1 *);
u4 dex_getFieldIdsSize(const u1 *);
u4 dex_getFieldIdsOff(const u1 *);
u4 dex_getMethodIdsSize(const u1 *);
u4 dex_getMethodIdsOff(const u1 *);
u4 dex_getClassDefsSize(const u1 *);
u4 dex_getClassDefsOff(const u1 *);
u4 dex_getDataSize(const u1 *);
u4 dex_getDataOff(const u1 *);

// Specific to CompactDex header
u4 dex_getFeatureFlags(const u1 *);
u4 dex_getDebugInfoOffsetsPos(const u1 *);
u4 dex_getDebugInfoOffsetsTableOffset(const u1 *);
u4 dex_getDebugInfoBase(const u1 *);
u4 dex_getOwnedDataBegin(const u1 *);
u4 dex_getOwnedDataEnd(const u1 *);

// Compute Dex file CRC
u4 dex_computeDexCRC(const u1 *, off_t);

// Repair Dex file CRC
void dex_repairDexCRC(const u1 *, off_t);

// Reads an unsigned LEB128 (Little-Endian Base 128) value, updating the
// given pointer to point just past the end of the read value. This function
// tolerates non-zero high-order bits in the fifth encoded byte.
u4 dex_readULeb128(const u1 **);

// Writes an unsigned LEB128 (Little-Endian Base 128) value, updating the
// given pointer to point just past the end of the written value.
u1 *dex_writeULeb128(u1 *dest, u4 value);

// Returns the first byte of a Leb128 value assuming that:
// (1) `end_ptr` points to the first byte after the Leb128 value, and
// (2) there is another Leb128 value before this one.
u1 *dex_reverseSearchULeb128(u1 *);

// Overwrite encoded Leb128 with a new value. The new value must be less than
// or equal to the old value to ensure that it fits the allocated space.
void dex_updateULeb128(u1 *, u4);

// Reads a signed LEB128 value, updating the given pointer to point
// just past the end of the read value. This function tolerates
// non-zero high-order bits in the fifth encoded byte.
s4 dex_readSLeb128(const u1 **);

// Get the offset of the first instruction for a given dexMethod
u4 dex_getFirstInstrOff(const u1 *, const dexMethod *);

// Read Leb128 class data header
void dex_readClassDataHeader(const u1 **, dexClassDataHeader *);

// Read a Leb128 class data field item
void dex_readClassDataField(const u1 **, dexField *);

// Read a Leb128 class data method item
void dex_readClassDataMethod(const u1 **, dexMethod *);

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
const char *dex_getFieldDeclaringClassDescriptor(const u1 *, const dexFieldId *);
const char *dex_getTypeDescriptor(const u1 *, const dexTypeId *);
const char *dex_getFieldName(const u1 *, const dexFieldId *);
const char *dex_getFieldTypeDescriptor(const u1 *, const dexFieldId *);
const char *dex_getMethodDeclaringClassDescriptor(const u1 *, const dexMethodId *);
const char *dex_getMethodName(const u1 *, const dexMethodId *);

// Dex disassembler methods
void dex_setDisassemblerStatus(bool);
bool dex_getDisassemblerStatus(void);
void dex_dumpInstruction(const u1 *, u2 *, u4, u4, bool);

// Get Dex data base address
const u1 *dex_getDataAddr(const u1 *);

// Functions to print information of primitive types (mainly used by disassembler)
void dex_dumpClassInfo(const u1 *, u4);
void dex_dumpMethodInfo(const u1 *, dexMethod *, u4, const char *);

// Converts a type descriptor to human-readable "dotted" form.  For
// example, "Ljava/lang/String;" becomes "java.lang.String", and
// "[I" becomes "int[]".  Also converts '$' to '.', which means this
// form can't be converted back to a descriptor.
char *dex_descriptorToDot(const char *);
char *dex_descriptorClassToDotLong(const char *);

// Converts the class name portion of a type descriptor to human-readable
// "dotted" form. For example, "Ljava/lang/String;" becomes "String".
char *dex_descriptorClassToDot(const char *);

// Helper method to decode CompactDex CodeItem fields and read the preheader if necessary. If
// decodeOnlyInsrCnt is specified then only the instruction count is decoded.
void dex_DecodeCDexFields(cdexCode *, u4 *, u2 *, u2 *, u2 *, u2 *, bool);

// Get CodeItem information from a DexMethod
void dex_getCodeItemInfo(const u1 *, dexMethod *, u2 **, u4 *);

u4 dex_decodeAccessFlagsFromDex(u4);

// Changes the dex class data pointed to by data_ptr it to not have any hiddenapi flags.
void dex_unhideAccessFlags(u1 *, u4, bool);

#endif
