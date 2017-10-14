# Vdex Extractor

Command line tool to decompile and extract Android Dex bytecode from Vdex files that are generated
along with OAT files when optimizing bytecode from dex2oat ART runtime compiler. Vdex file format
has been introduced in the Oreo (API-26) build. More information is available
[here](https://android-review.googlesource.com/#/c/264514/).


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
    vdexExtractor ver. 0.1.1

    Anestis Bechtsoudis <anestis@census-labs.com>
  Copyright 2017 by CENSUS S.A. All Rights Reserved.

  -i,  --input=<path>  : input dir (1 max depth) or single file
  -o,  --output=<path> : output path (default is same as input)
  -f,  --file-override : allow output file override if already exists
  -u,  --unquicken     : unquicken bytecode (beta)
  -h,  --help          : this help
  -v,  --debug=LEVEL   : debug level (0 - FATAL ... 5 - VDEBUG), default: '3' (INFO)
```


## Bytecode Unquickening

The Vdex file includes all quick_info data (old vtable) required to revert the dex-to-dex
transformations applied during bytecode optimization. The idea here is to create a quick standalone
tool capable to revert optimized bytecode, that does not require building the entire libart from
AOSP.

The Vdex fully unquicken functionality has been also implemented as part of the AOSP oatdump libart
tool. The upstream contribution is available
[here](https://android-review.googlesource.com/#/c/platform/art/+/505156/). If you want to use
oatdump with Oreo release you can use the corresponding patch
[here](https://gist.github.com/anestisb/71d6b0496912f801533dec9d264aa409).


## Changelog

* __0.X.X__ - TBC
  * Unquicken decompiler stable release
  * Implement Dex bytecode disassembler
* __0.1.1__ - 13 October 2017
  * Unquicken decompiler beta release
* __0.1.0__ - 8 October 2017
  * Initial release


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
