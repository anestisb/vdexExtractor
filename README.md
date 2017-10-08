# VDEX Extractor

Command line tool to extract Android DEX bytecode from VDEX files that are
generated along with OAT files when optimizing bytecode from dex2oat ART runtime
compiler. VDEX file format has been introduced in the Oreo (API-26) build. More
information is available
[here](https://android-review.googlesource.com/#/c/264514/).


## Compile

* Clone this repository
* Install Android NDK if you want to cross-compile for Android devices
* Invoke `make.sh` bash script with desired build target
  * `$ ./make.sh` - default system compiler
  * `$ ./make.sh gcc` - prefer gcc
  * `$ ./make.sh clang` - prefer clang
  * `$ ./make.sh cross-android` - cross-compile for Android with NDK
* Executables are copied under the `bin` directory


## Usage

```
$ bin/vdexExtractor -h
    vdexExtractor ver. 0.1.0

    Anestis Bechtsoudis <anestis@census-labs.com>
  Copyright 2017 by CENSUS S.A. All Rights Reserved.

  -i,  --input=<path>  : input dir (1 max depth) or single file
  -o,  --output=<path> : output path (default is same as input)
  -u,  --unquicken     : unquicken bytecode (under development)
  -h,  --help          : this help
  -v,  --debug=LEVEL   : debug level (0 - FATAL ... 4 - DEBUG), default: '3' (INFO)
```


## Bytecode Unquickening

The VDEX file includes all quick_info data (old vtable) required to revert the
dex-to-dex transformations applied during bytecode optimization. The idea here
is to create a quick standalone tool capable to revert optimized bytecode, that
does not require building the entire libart from AOSP.

This feature is currently under development. If you want to unquicken Oreo
optimized bytecode you can use the oatdump patch that is available
[here](https://gist.github.com/anestisb/71d6b0496912f801533dec9d264aa409).


## Changelog

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
