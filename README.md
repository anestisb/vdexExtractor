# Vdex Extractor

Command line tool to decompile and extract Android Dex bytecode from Vdex files that are generated
along with Oat files when optimizing bytecode from dex2oat ART runtime compiler. Vdex file format
has been introduced in the Oreo (API-26) build. More information is available
[here](https://android-review.googlesource.com/#/c/264514/). It should be noted that Oat files are
no longer storing the matching Dex files inside their `.rodata` section. Instead they're always
paired with a matching Vdex file.


## Compile

* Clone this repository
* Install Android NDK if you want to cross-compile for Android devices
* Invoke `make.sh` bash script with desired build target
  * `$ ./make.sh` - if CC not defined from env use gcc by default
  * `$ ./make.sh gcc` - compile with gcc
  * `$ ./make.sh clang` - compile with clang
  * `$ ./make.sh cross-android` - cross-compile (armeabi-v7a, arm64-v8a, x86 &
  x86_64) for Android with NDK
* Executables are copied under the `bin` directory
* For debug builds use `$ DEBUG=true ./make.sh`


## Usage

```
$ bin/vdexExtractor -h
              vdexExtractor ver. 0.3.0
    Anestis Bechtsoudis <anestis@census-labs.com>
  Copyright 2017 by CENSUS S.A. All Rights Reserved.

 -i, --input=<path>   : input dir (1 max depth) or single file
 -o, --output=<path>  : output path (default is same as input)
 -f, --file-override  : allow output file override if already exists
 -u, --unquicken      : enable unquicken bytecode decompiler
 -D, --dump-deps      : dump verified dependencies information
 -d, --disassemble    : enable bytecode disassembler
 -v, --debug=LEVEL    : log level (0 - FATAL ... 4 - DEBUG), default: '3' (INFO)
 -l, --log-file=<path>: save disassembler and/or verified dependencies output to log file (default is STDOUT)
 -h, --help           : this help
```


## Bytecode Unquickening Decompiler

The Vdex file includes all quick_info data (old vtable) required to revert the dex-to-dex
transformations applied during bytecode optimization. The idea here is to create a quick standalone
tool capable to revert optimized bytecode, that does not require building the entire libart from
AOSP.

The Vdex fully unquicken functionality has been also implemented as part of the AOSP oatdump libart
tool. The upstream contribution is available
[here](https://android.googlesource.com/platform/art/+/a1f56a8dddb88f5377a7dd4ec79640103c713d30).
If you want to use oatdump with Oreo release you can use the corresponding patch
[here](https://gist.github.com/anestisb/71d6b0496912f801533dec9d264aa409) or fork and build (inside
and AOSP_SRC_ROOT workspace) the oreo-release branch of the
[oatdump++](https://github.com/anestisb/oatdump_plus/tree/oreo-release) tool.


## Verified Dependencies Iterator

When the Dex bytecode files are compiled (optimized) for the first time, dex2oat executes the
verification dependencies collector as part of the MethodVerifier The verification dependencies
collector class is used to record resolution outcomes and type assignability tests of
classes/methods/fields defined in the classpath. The compilation driver initializes the class and
registers all Dex files which are being compiled. Classes defined in Dex files outside of this set
(or synthesized classes without associated Dex files) are considered being in the classpath. All
recorded dependencies are stored in the generated Vdex file along with the corresponding Oat file
from the OatWriter class.

vdexExtractor tool integrates a Vdex dependencies walker function that is capable to iterate all
dependencies information and dump them in a human readable format. The following snippet
demonstrates a dependencies dump example of a sample Vdex file.

```
$ bin/vdexExtractor -i /tmp/CarrierConfig.vdex -o /tmp -D -f
[INFO] Processing 1 file(s) from /tmp/CarrierConfig.vdex
 ------ Vdex Header Info ------
 magic header & version      : vdex-006
 number of dex files         : 1 (1)
 dex size (overall)          : 1300 (4864)
 verifier dependencies size  : f8 (248)
 verifier dependencies offset: 131c (4892)
 quickening info size        : 86 (134)
 quickening info offset      : 1414 (5140)
 dex files info              :
   [0] location checksum : 788135e0 (2021733856)
 ---- EOF Vdex Header Info ----
 ------- Vdex Deps Info -------
 dex file #0
  extra strings: number_of_strings=3
   0000: 'Landroid/os/BaseBundle;'
   0001: 'Landroid/content/ContextWrapper;'
   0002: 'Ljava/lang/Throwable;'
  assignable type sets: number_of_sets=7
   0000: 'Ljava/io/IOException;' must be assignable to 'Ljava/lang/Exception;'
   0001: 'Lorg/xmlpull/v1/XmlPullParserException;' must be assignable to 'Ljava/lang/Exception;'
   0002: 'Landroid/os/PersistableBundle;' must be assignable to 'Landroid/os/BaseBundle;'
   0003: 'Landroid/service/carrier/CarrierService;' must be assignable to 'Landroid/content/ContextWrapper;'
   0004: 'Ljava/io/IOException;' must be assignable to 'Ljava/lang/Throwable;'
   0005: 'Ljava/lang/Exception;' must be assignable to 'Ljava/lang/Throwable;'
   0006: 'Lorg/xmlpull/v1/XmlPullParserException;' must be assignable to 'Ljava/lang/Throwable;'
  unassignable type sets: number_of_sets=0
  class dependencies: number_of_classes=18
   0000: 'Landroid/content/Context;' 'must' be resolved with access flags '1'
   0001: 'Landroid/content/res/AssetManager;' 'must' be resolved with access flags '1'
   0002: 'Landroid/content/res/Resources;' 'must' be resolved with access flags '1'
   0003: 'Landroid/os/Build;' 'must' be resolved with access flags '1'
   0004: 'Landroid/os/PersistableBundle;' 'must' be resolved with access flags '1'
   0005: 'Landroid/service/carrier/CarrierIdentifier;' 'must' be resolved with access flags '1'
   0006: 'Landroid/service/carrier/CarrierService;' 'must' be resolved with access flags '1'
   0007: 'Landroid/text/TextUtils;' 'must' be resolved with access flags '1'
   0008: 'Landroid/util/Log;' 'must' be resolved with access flags '1'
   0009: 'Ljava/io/IOException;' 'must' be resolved with access flags '1'
   0010: 'Ljava/lang/Exception;' 'must' be resolved with access flags '1'
   0011: 'Ljava/lang/String;' 'must' be resolved with access flags '1'
   0012: 'Ljava/lang/StringBuilder;' 'must' be resolved with access flags '1'
   0013: 'Ljava/util/regex/Matcher;' 'must' be resolved with access flags '1'
   0014: 'Ljava/util/regex/Pattern;' 'must' be resolved with access flags '1'
   0015: 'Lorg/xmlpull/v1/XmlPullParser;' 'must' be resolved with access flags '513'
   0016: 'Lorg/xmlpull/v1/XmlPullParserException;' 'must' be resolved with access flags '1'
   0017: 'Lorg/xmlpull/v1/XmlPullParserFactory;' 'must' be resolved with access flags '1'
  field dependencies: number_of_fields=1
   0000: 'Landroid/os/Build;'->'DEVICE':'Ljava/lang/String;' is expected to be in class 'Landroid/os/Build;' and have the access flags '9'
  direct method dependencies: number_of_methods=9
   0000: 'Landroid/os/PersistableBundle;'->'<init>':'()V' is expected to be in class 'Landroid/os/PersistableBundle;', have the access flags '1', and be of kind 'direct'
   0001: 'Landroid/os/PersistableBundle;'->'restoreFromXml':'(Lorg/xmlpull/v1/XmlPullParser;)Landroid/os/PersistableBundle;' is expected to be in class 'Landroid/os/PersistableBundle;', have the access flags '9', and be of kind 'direct'
   0002: 'Landroid/service/carrier/CarrierService;'->'<init>':'()V' is expected to be in class 'Landroid/service/carrier/CarrierService;', have the access flags '1', and be of kind 'direct'
   0003: 'Landroid/text/TextUtils;'->'isEmpty':'(Ljava/lang/CharSequence;)Z' is expected to be in class 'Landroid/text/TextUtils;', have the access flags '9', and be of kind 'direct'
   0004: 'Landroid/util/Log;'->'d':'(Ljava/lang/String;Ljava/lang/String;)I' is expected to be in class 'Landroid/util/Log;', have the access flags '9', and be of kind 'direct'
   0005: 'Landroid/util/Log;'->'e':'(Ljava/lang/String;Ljava/lang/String;)I' is expected to be in class 'Landroid/util/Log;', have the access flags '9', and be of kind 'direct'
   0006: 'Ljava/lang/StringBuilder;'->'<init>':'()V' is expected to be in class 'Ljava/lang/StringBuilder;', have the access flags '1', and be of kind 'direct'
   0007: 'Ljava/util/regex/Pattern;'->'compile':'(Ljava/lang/String;I)Ljava/util/regex/Pattern;' is expected to be in class 'Ljava/util/regex/Pattern;', have the access flags '9', and be of kind 'direct'
   0008: 'Lorg/xmlpull/v1/XmlPullParserFactory;'->'newInstance':'()Lorg/xmlpull/v1/XmlPullParserFactory;' is expected to be in class 'Lorg/xmlpull/v1/XmlPullParserFactory;', have the access flags '9', and be of kind 'direct'
  virtual method dependencies: number_of_methods=20
   0000: 'Landroid/content/Context;'->'getAssets':'()Landroid/content/res/AssetManager;' is expected to be in class 'Landroid/content/Context;', have the access flags '1', and be of kind 'virtual'
   0001: 'Landroid/content/Context;'->'getResources':'()Landroid/content/res/Resources;' is expected to be in class 'Landroid/content/Context;', have the access flags '1', and be of kind 'virtual'
   0002: 'Landroid/content/res/AssetManager;'->'open':'(Ljava/lang/String;)Ljava/io/InputStream;' is expected to be in class 'Landroid/content/res/AssetManager;', have the access flags '1', and be of kind 'virtual'
   0003: 'Landroid/content/res/Resources;'->'getXml':'(I)Landroid/content/res/XmlResourceParser;' is expected to be in class 'Landroid/content/res/Resources;', have the access flags '1', and be of kind 'virtual'
   0004: 'Landroid/os/PersistableBundle;'->'putAll':'(Landroid/os/PersistableBundle;)V' is expected to be in class 'Landroid/os/BaseBundle;', have the access flags '1', and be of kind 'virtual'
   0005: 'Landroid/service/carrier/CarrierIdentifier;'->'getGid1':'()Ljava/lang/String;' is expected to be in class 'Landroid/service/carrier/CarrierIdentifier;', have the access flags '1', and be of kind 'virtual'
   0006: 'Landroid/service/carrier/CarrierIdentifier;'->'getGid2':'()Ljava/lang/String;' is expected to be in class 'Landroid/service/carrier/CarrierIdentifier;', have the access flags '1', and be of kind 'virtual'
   0007: 'Landroid/service/carrier/CarrierIdentifier;'->'getImsi':'()Ljava/lang/String;' is expected to be in class 'Landroid/service/carrier/CarrierIdentifier;', have the access flags '1', and be of kind 'virtual'
   0008: 'Landroid/service/carrier/CarrierIdentifier;'->'getMcc':'()Ljava/lang/String;' is expected to be in class 'Landroid/service/carrier/CarrierIdentifier;', have the access flags '1', and be of kind 'virtual'
   0009: 'Landroid/service/carrier/CarrierIdentifier;'->'getMnc':'()Ljava/lang/String;' is expected to be in class 'Landroid/service/carrier/CarrierIdentifier;', have the access flags '1', and be of kind 'virtual'
   0010: 'Landroid/service/carrier/CarrierIdentifier;'->'getSpn':'()Ljava/lang/String;' is expected to be in class 'Landroid/service/carrier/CarrierIdentifier;', have the access flags '1', and be of kind 'virtual'
   0011: 'Lcom/android/carrierconfig/DefaultCarrierConfigService;'->'getApplicationContext':'()Landroid/content/Context;' is expected to be in class 'Landroid/content/ContextWrapper;', have the access flags '1', and be of kind 'virtual'
   0012: 'Ljava/lang/Exception;'->'toString':'()Ljava/lang/String;' is expected to be in class 'Ljava/lang/Throwable;', have the access flags '1', and be of kind 'virtual'
   0013: 'Ljava/lang/String;'->'equals':'(Ljava/lang/Object;)Z' is expected to be in class 'Ljava/lang/String;', have the access flags '1', and be of kind 'virtual'
   0014: 'Ljava/lang/String;'->'equalsIgnoreCase':'(Ljava/lang/String;)Z' is expected to be in class 'Ljava/lang/String;', have the access flags '1', and be of kind 'virtual'
   0015: 'Ljava/lang/StringBuilder;'->'append':'(Ljava/lang/String;)Ljava/lang/StringBuilder;' is expected to be in class 'Ljava/lang/StringBuilder;', have the access flags '1', and be of kind 'virtual'
   0016: 'Ljava/lang/StringBuilder;'->'toString':'()Ljava/lang/String;' is expected to be in class 'Ljava/lang/StringBuilder;', have the access flags '1', and be of kind 'virtual'
   0017: 'Ljava/util/regex/Matcher;'->'matches':'()Z' is expected to be in class 'Ljava/util/regex/Matcher;', have the access flags '1', and be of kind 'virtual'
   0018: 'Ljava/util/regex/Pattern;'->'matcher':'(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;' is expected to be in class 'Ljava/util/regex/Pattern;', have the access flags '1', and be of kind 'virtual'
   0019: 'Lorg/xmlpull/v1/XmlPullParserFactory;'->'newPullParser':'()Lorg/xmlpull/v1/XmlPullParser;' is expected to be in class 'Lorg/xmlpull/v1/XmlPullParserFactory;', have the access flags '1', and be of kind 'virtual'
  interface method dependencies: number_of_methods=6
   0000: 'Lorg/xmlpull/v1/XmlPullParser;'->'getAttributeCount':'()I' is expected to be in class 'Lorg/xmlpull/v1/XmlPullParser;', have the access flags '1', and be of kind 'interface'
   0001: 'Lorg/xmlpull/v1/XmlPullParser;'->'getAttributeName':'(I)Ljava/lang/String;' is expected to be in class 'Lorg/xmlpull/v1/XmlPullParser;', have the access flags '1', and be of kind 'interface'
   0002: 'Lorg/xmlpull/v1/XmlPullParser;'->'getAttributeValue':'(I)Ljava/lang/String;' is expected to be in class 'Lorg/xmlpull/v1/XmlPullParser;', have the access flags '1', and be of kind 'interface'
   0003: 'Lorg/xmlpull/v1/XmlPullParser;'->'getName':'()Ljava/lang/String;' is expected to be in class 'Lorg/xmlpull/v1/XmlPullParser;', have the access flags '1', and be of kind 'interface'
   0004: 'Lorg/xmlpull/v1/XmlPullParser;'->'next':'()I' is expected to be in class 'Lorg/xmlpull/v1/XmlPullParser;', have the access flags '1', and be of kind 'interface'
   0005: 'Lorg/xmlpull/v1/XmlPullParser;'->'setInput':'(Ljava/io/InputStream;Ljava/lang/String;)V' is expected to be in class 'Lorg/xmlpull/v1/XmlPullParser;', have the access flags '1', and be of kind 'interface'
  unverified classes: number_of_classes=0
 ----- EOF Vdex Deps Info -----
[INFO] 1 out of 1 Vdex files have been processed
[INFO] 1 Dex files have been extracted in total
[INFO] Extracted Dex files are available in '/tmp'
```


## Integrated Disassembler

To debug the decompiler and assist the Dex bytecode investigation tasks, a light disassembler has
been implemented. The disassembler output is very similar to the one provided by the AOSP dexdump2
utility of the `platform/art` project. The disassembler can be used independently of the
unquickening decompiler.

A sample output is illustrated in the following snippet. Lines prefixed with `[new]` illustrate the
output of the decompiled instruction (previous line) located in that offset. Notice that all the
quickened offsets and vtable references have been reverted back to original signatures and
prototypes.

```
$ bin/vdexExtractor -i /tmp/Videos.vdex -o /tmp -f -u -v5 -d -l /tmp/dis.log
[INFO] Processing 1 file(s) from /tmp/Videos.vdex
[INFO] 1 out of 1 Vdex files have been processed
[INFO] 2 Dex files have been extracted in total
[INFO] Extracted Dex files are available in '/tmp'
$ head -110 /tmp/dis.log
[DEBUG] [1185] 2017/10/18 16:30:04 (vdexExtractor.c:168 main) Processing '/tmp/Videos.vdex'
[DEBUG] [1185] 2017/10/18 16:30:04 (vdex.c:36 vdex_isVersionValid) Vdex version '006' detected
 ------ Vdex Header Info ------
 magic header & version      : vdex-006
 number of dex files         : 2 (2)
 dex size (overall)          : 8f0e4c (9375308)
 verifier dependencies size  : df5c (57180)
 verifier dependencies offset: 8f0e6c (9375340)
 quickening info size        : 100843 (1050691)
 quickening info offset      : 8fedc8 (9432520)
 dex files info              :
   [0] location checksum : 34315154 (875647316)
   [1] location checksum : 1e8f2991 (512698769)
 ------------------------------
[DEBUG] [1185] 2017/10/18 16:30:04 (vdex.c:80 vdex_GetNextDexFileData) Processing first Dex file at offset:0x20
 ------ Dex Header Info ------
 magic        : dex-035
 checksum     : e14de163 (3779977571)
 signature    : 9a91f8e5f2afe2c6b5c2b4853832d3c5ed01aef8
 fileSize     : 8ca638 (9217592)
 headerSize   : 70 (112)
 endianTag    : 12345678 (305419896)
 linkSize     : 0 (0)
 linkOff      : 0 (0)
 mapOff       : 8ca568 (9217384)
 stringIdsSize: ef06 (61190)
 stringIdsOff : 70 (112)
 typeIdsSize  : 29f4 (10740)
 typeIdsOff   : 3bc88 (244872)
 protoIdsSize : 3df9 (15865)
 protoIdsOff  : 46458 (287832)
 fieldIdsSize : a79d (42909)
 fieldIdsOff  : 74c04 (478212)
 methodIdsSize: fed7 (65239)
 methodIdsOff : c88ec (821484)
 classDefsSize: 2288 (8840)
 classDefsOff : 147fa4 (1343396)
 dataSize     : 73d594 (7591316)
 dataOff      : 18d0a4 (1626276)
 -----------------------------
[DEBUG] [1185] 2017/10/18 16:30:04 (dex.c:313 dex_isValidDexMagic) Dex version '035' detected
 file #0: classDefsSize=8840
  class #0: a.a ('La$a;')
   access=0601 (PUBLIC INTERFACE ABSTRACT)
   source_file=SourceFile, class_data_off=851907 (8722695)
   static_fields=0, instance_fields=0, direct_methods=0, virtual_methods=2
   virtual_method #0: onMenuItemSelected (La;Landroid/view/MenuItem;)Z
    access=0401 (PUBLIC ABSTRACT)
    codeOff=0 (0)
   virtual_method #1: invokeItem (Landroid/support/v7/view/menu/MenuItemImpl;)Z
    access=0401 (PUBLIC ABSTRACT)
    codeOff=0 (0)
  class #1: a.b ('La$b;')
   access=0601 (PUBLIC INTERFACE ABSTRACT)
   source_file=SourceFile, class_data_off=851913 (8722707)
   static_fields=0, instance_fields=0, direct_methods=0, virtual_methods=1
   virtual_method #0: invokeItem (Landroid/support/v7/view/menu/MenuItemImpl;)Z
    access=0401 (PUBLIC ABSTRACT)
    codeOff=0 (0)
  class #2: SupportMenu ('Landroid/support/v4/internal/view/SupportMenu;')
   access=0601 (PUBLIC INTERFACE ABSTRACT)
   source_file=SourceFile, class_data_off=0 (0)
  class #3: a ('La;')
   access=0001 (PUBLIC)
   source_file=SourceFile, class_data_off=85191b (8722715)
   static_fields=1, instance_fields=25, direct_methods=12, virtual_methods=74
   direct_method #0: <clinit> ()V
    access=10008 (STATIC CONSTRUCTOR)
    codeOff=1abb50 (1751888)
    quickening_size=0 (0)
      1abb60: 1260                                   |0000: const/4 v0, #int 6 // #6
      1abb62: 2300 e426                              |0001: new-array v0, v0, [I // type@26e4
      1abb66: 2600 0700 0000                         |0003: fill-array-data v0, 0000000a // +00000000
      1abb6c: 6900 1900                              |0006: sput-object v0, La;.sCategoryToOrder:[I // field@0019
      1abb70: 7300                                   |0008: return-void-no-barrier
[new] 1abb70: 0e00                                   |0008: return-void
      1abb72: 0000                                   |0009: nop // spacer
      1abb74: 0003 0400 0600 0000 0100 0000 0400 ... |000a: array-data (16 units)
   direct_method #1: invokeItem (Landroid/support/v7/view/menu/MenuItemImpl;)Z
    access=10001 (PUBLIC CONSTRUCTOR)
    codeOff=1abb94 (1751956)
    quickening_size=23 (35)
      1abba4: 1211                                   |0000: const/4 v1, #int 1 // #1
      1abba6: 1200                                   |0001: const/4 v0, #int 0 // #0
      1abba8: 7010 dbf9 0200                         |0002: invoke-direct {v2}, Ljava/lang/Object;.<init>:()V // method@f9db
      1abbae: e620 4000                              |0005: iput-quick v0, v2, [obj+0040]
[new] 1abbae: 5920 0400                              |0005: iput v0, v2, La;.mDefaultShowAsAction:I // field@0004
      1abbb2: eb20 4a00                              |0007: iput-boolean-quick v0, v2, [obj+004a]
[new] 1abbb2: 5c20 1200                              |0007: iput-boolean v0, v2, La;.mPreventDispatchingItemsChanged:Z // field@0012
      1abbb6: eb20 4700                              |0009: iput-boolean-quick v0, v2, [obj+0047]
[new] 1abbb6: 5c20 0d00                              |0009: iput-boolean v0, v2, La;.mItemsChangedWhileDispatchPrevented:Z // field@000d
      1abbba: eb20 4d00                              |000b: iput-boolean-quick v0, v2, [obj+004d]
[new] 1abbba: 5c20 1600                              |000b: iput-boolean v0, v2, La;.mStructureChangedWhileDispatchPrevented:Z // field@0016
      1abbbe: eb20 4800                              |000d: iput-boolean-quick v0, v2, [obj+0048]
[new] 1abbbe: 5c20 0f00                              |000d: iput-boolean v0, v2, La;.mOptionalIconsVisible:Z // field@000f
      1abbc2: eb20 4500                              |000f: iput-boolean-quick v0, v2, [obj+0045]
[new] 1abbc2: 5c20 0a00                              |000f: iput-boolean v0, v2, La;.mIsClosing:Z // field@000a
      1abbc6: 2200 fe25                              |0011: new-instance v0, Ljava/util/ArrayList; // type@25fe
      1abbca: 7010 6bfb 0000                         |0013: invoke-direct {v0}, Ljava/util/ArrayList;.<init>:()V // method@fb6b
      1abbd0: e820 3800                              |0016: iput-object-quick v0, v2, [obj+0038]
[new] 1abbd0: 5b20 1700                              |0016: iput-object v0, v2, La;.mTempShortcutItemList:Ljava/util/ArrayList; // field@0017
      1abbd4: 2200 2c26                              |0018: new-instance v0, Ljava/util/concurrent/CopyOnWriteArrayList; // type@262c
      1abbd8: 7010 cdfc 0000                         |001a: invoke-direct {v0}, Ljava/util/concurrent/CopyOnWriteArrayList;.<init>:()V // method@fccd
      1abbde: e820 3000                              |001d: iput-object-quick v0, v2, [obj+0030]
[new] 1abbde: 5b20 1100                              |001d: iput-object v0, v2, La;.mPresenters:Ljava/util/concurrent/CopyOnWriteArrayList; // field@0011
      1abbe2: e823 1000                              |001f: iput-object-quick v3, v2, [obj+0010]
[new] 1abbe2: 5b23 0200                              |001f: iput-object v3, v2, La;.mContext:Landroid/content/Context; // field@0002
      1abbe6: e910 5500 0300                         |0021: invoke-virtual-quick {v3}, [0055] // vtable #0055
[new] 1abbe6: 6e10 6502 0300                         |0021: invoke-virtual {v3}, Landroid/content/Context;.getResources:()Landroid/content/res/Resources; // method@0265
      1abbec: 0c00                                   |0024: move-result-object v0
```


## Utility Scripts

* **scripts/extract-apps-from-device.sh**

  Extract ART compiler output resources (oat, art, vdex) of installed packages (user and system)
  from a connected Android device. Also supports extracting APK archives of installed packages. Some
  system app data might fail to extract without root access due to applied DAC permissions.

  ```
  $ scripts/extract-apps-from-device.sh -h
    Usage: extract-apps-from-device.sh [options]
      options:
        -o|--output <dir>  : Output directory to save extracted data (default is '.')
        -d|--device <devID>: Device serial to use instead of default interactive selection
        --system-apps      : Extract system apps too (default is user apps only)
        --apks             : Extract apks (default is optimized files only)
        -h|--help          : This help message
  $ scripts/extract-apps-from-device.sh --system-apps -o /tmp/art_data --apks
  [INFO]: Enumerating connected Android devices
  [INFO]: Trying to extract data from '163' packages
  [INFO]: Extracted data stored under '/tmp/art_data'
  ```


## Changelog

* __0.3.1__ - TBC
  * Add timer utility functions to measure time spend to unquicken each input Vdex file
  * Use external log file only for disassembler & verified dependencies information output
  * Logging facility improvements
  * Improve code quality by removing duplicate code
* __0.3.0__ - 28 October 2017
  * Implement Vdex verified dependencies information iterator (`-D, --dump-deps`)
  * Enable Dex disassembler without requiring to unquicken bytecode
  * Improve Dex disassembler output by resolving class & method definitions
  * Improve Dex disassembler output by annotating classes & methods access flags
  * Fixed a bug when printing number of class fields and method from Dex disassembler
  * Utility script to automate extraction of ART compiler output resources from a device
  * Dex file API improvements
* __0.2.3__ - 16 October 2017
  * Improve disassembler output when decompiling NOP instructions (effectively ignore spacers)
* __0.2.2__ - 16 October 2017
  * Fix UAF bug when processing multiple files
* __0.2.1__ - 16 October 2017
  * Option to save output to log file instead of (default) STDOUT (`-l, --log-file`)
  * Dump Vdex header information with verbose debug option
  * Fix minor memory leaks & memory corruptions in disassembler engine
* __0.2.0__ - 16 October 2017
  * Unquicken decompiler stable release (`-u, --unquicken`)
  * Implement Dex bytecode disassembler (`-d, --disassemble`)
* __0.1.1__ - 13 October 2017
  * Unquicken decompiler beta release (`-u, --unquicken`)
  * Allow override of output Dex files (`-f, --file-override`)
* __0.1.0__ - 8 October 2017
  * Initial release


## ToDo

* Disassembler performance & usability improvements


## License

```
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
```
