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

#ifndef _DEX_MODIFIERS_H_
#define _DEX_MODIFIERS_H_

#include "common.h"

static const u4 kAccPublic = 0x0001;        // class, field, method, ic
static const u4 kAccPrivate = 0x0002;       // field, method, ic
static const u4 kAccProtected = 0x0004;     // field, method, ic
static const u4 kAccStatic = 0x0008;        // field, method, ic
static const u4 kAccFinal = 0x0010;         // class, field, method, ic
static const u4 kAccSynchronized = 0x0020;  // method (only allowed on natives)
static const u4 kAccSuper = 0x0020;         // class (not used in dex)
static const u4 kAccVolatile = 0x0040;      // field
static const u4 kAccBridge = 0x0040;        // method (1.5)
static const u4 kAccTransient = 0x0080;     // field
static const u4 kAccVarargs = 0x0080;       // method (1.5)
static const u4 kAccNative = 0x0100;        // method
static const u4 kAccInterface = 0x0200;     // class, ic
static const u4 kAccAbstract = 0x0400;      // class, method, ic
static const u4 kAccStrict = 0x0800;        // method
static const u4 kAccSynthetic = 0x1000;     // class, field, method, ic
static const u4 kAccAnnotation = 0x2000;    // class, ic (1.5)
static const u4 kAccEnum = 0x4000;          // class, field, ic (1.5)

static const u4 kAccJavaFlagsMask = 0xffff;  // bits set from Java sources (low 16)

// The following flags are used to insert hidden API access flags into boot
// class path dex files. They are decoded by DexFile::ClassDataItemIterator and
// removed from the access flags before used by the runtime.
static const u4 kAccDexHiddenBit = 0x00000020;        // field, method (not native)
static const u4 kAccDexHiddenBitNative = 0x00000200;  // method (native)

static const u4 kAccConstructor = 0x00010000;           // method (dex only) <(cl)init>
static const u4 kAccDeclaredSynchronized = 0x00020000;  // method (dex only)
static const u4 kAccClassIsProxy = 0x00040000;          // class  (dex only)
// Set to indicate that the ArtMethod is obsolete and has a different DexCache + DexFile from its
// declaring class. This flag may only be applied to methods.
static const u4 kAccObsoleteMethod = 0x00040000;  // method (runtime)
// Used by a method to denote that its execution does not need to go through slow path interpreter.
static const u4 kAccSkipAccessChecks = 0x00080000;  // method (runtime, not native)
// Used by a class to denote that the verifier has attempted to check it at least once.
static const u4 kAccVerificationAttempted = 0x00080000;  // class (runtime)
static const u4 kAccSkipHiddenApiChecks = 0x00100000;    // class (runtime)
// This is set by the class linker during LinkInterfaceMethods. It is used by a method to represent
// that it was copied from its declaring class into another class. All methods marked kAccMiranda
// and kAccDefaultConflict will have this bit set. Any kAccDefault method contained in the methods_
// array of a concrete class will also have this bit set.
static const u4 kAccCopied = 0x00100000;   // method (runtime)
static const u4 kAccMiranda = 0x00200000;  // method (runtime, not native)
static const u4 kAccDefault = 0x00400000;  // method (runtime)
// Native method flags are set when linking the methods based on the presence of the
// @dalvik.annotation.optimization.{Fast,Critical}Native annotations with build visibility.
// Reuse the values of kAccSkipAccessChecks and kAccMiranda which are not used for native methods.
static const u4 kAccFastNative = 0x00080000;      // method (runtime; native only)
static const u4 kAccCriticalNative = 0x00200000;  // method (runtime; native only)

// Set by the JIT when clearing profiling infos to denote that a method was previously warm.
static const u4 kAccPreviouslyWarm = 0x00800000;  // method (runtime)

// This is set by the class linker during LinkInterfaceMethods. Prior to that point we do not know
// if any particular method needs to be a default conflict. Used to figure out at runtime if
// invoking this method will throw an exception.
static const u4 kAccDefaultConflict = 0x01000000;  // method (runtime)

// Set by the verifier for a method we do not want the compiler to compile.
static const u4 kAccCompileDontBother = 0x02000000;  // method (runtime)

// Set by the verifier for a method that could not be verified to follow structured locking.
static const u4 kAccMustCountLocks = 0x04000000;  // method (runtime)

// Set by the class linker for a method that has only one implementation for a
// virtual call.
static const u4 kAccSingleImplementation = 0x08000000;  // method (runtime)

static const u4 kAccHiddenApiBits = 0x30000000;  // field, method

// Not currently used, except for intrinsic methods where these bits
// are part of the intrinsic ordinal.
static const u4 kAccMayBeUnusedBits = 0x40000000;

// Set by the compiler driver when compiling boot classes with instrinsic methods.
static const u4 kAccIntrinsic = 0x80000000;  // method (runtime)

// Special runtime-only flags.
// Interface and all its super-interfaces with default methods have been recursively initialized.
static const u4 kAccRecursivelyInitialized = 0x20000000;
// Interface declares some default method.
static const u4 kAccHasDefaultMethod = 0x40000000;
// class/ancestor overrides finalize()
static const u4 kAccClassIsFinalizable = 0x80000000;

// Continuous sequence of bits used to hold the ordinal of an intrinsic method. Flags
// which overlap are not valid when kAccIntrinsic is set.
#define kAccIntrinsicBits                                                                    \
  (kAccMayBeUnusedBits | kAccHiddenApiBits | kAccSingleImplementation | kAccMustCountLocks | \
   kAccCompileDontBother | kAccDefaultConflict | kAccPreviouslyWarm)

// Valid (meaningful) bits for a field.
#define kAccValidFieldFlags                                                           \
  (kAccPublic | kAccPrivate | kAccProtected | kAccStatic | kAccFinal | kAccVolatile | \
   kAccTransient | kAccSynthetic | kAccEnum)

// Valid (meaningful) bits for a method.
#define kAccValidMethodFlags                                                              \
  (kAccPublic | kAccPrivate | kAccProtected | kAccStatic | kAccFinal | kAccSynchronized | \
   kAccBridge | kAccVarargs | kAccNative | kAccAbstract | kAccStrict | kAccSynthetic |    \
   kAccConstructor | kAccDeclaredSynchronized)

// Valid (meaningful) bits for a class (not interface).
// Note 1. These are positive bits. Other bits may have to be zero.
// Note 2. Inner classes can expose more access flags to Java programs. That is handled by libcore.
#define kAccValidClassFlags \
  (kAccPublic | kAccFinal | kAccSuper | kAccAbstract | kAccSynthetic | kAccEnum)

// Valid (meaningful) bits for an interface.
// Note 1. Annotations are interfaces.
// Note 2. These are positive bits. Other bits may have to be zero.
// Note 3. Inner classes can expose more access flags to Java programs. That is handled by libcore.
#define kAccValidInterfaceFlags \
  (kAccPublic | kAccInterface | kAccAbstract | kAccSynthetic | kAccAnnotation)

#define kAccVisibilityFlags (kAccPublic | kAccPrivate | kAccProtected)

#endif
