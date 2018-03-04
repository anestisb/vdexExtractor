#!/usr/bin/env bash
#
# vdexExtractor
# -----------------------------------------
#
# Anestis Bechtsoudis <anestis@census-labs.com>
# Copyright 2017 - 2018 by CENSUS S.A. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

set -e # fail on unhandled error
set -u # fail on undefined variable
#set -x # debug

readonly TOOL_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
readonly TMP_WORK_DIR=$(mktemp -d /tmp/vdex-extractor.XXXXXX) || exit 1
readonly VDEX_EXTRACTOR_BIN="$TOOL_ROOT/../bin/vdexExtractor"

declare -ar SYS_TOOLS=("mkdir" "dirname" "sed" "grep" "unzip")

info()   { echo -e  "[INFO]: $*" 1>&2; }
warn()   { echo -e  "[WARN]: $*" 1>&2; }
error()  { echo -e  "[ERR ]: $*" 1>&2; }
debug()  { echo -e  "[DBG ]: $*" 1>&2; }
log()    { echo -e  "        $*" 1>&2; }
userIn() { echo -en "[IN  ]: $*" 1>&2; }

abort() {
  rm -rf "$TMP_WORK_DIR"
  exit "$1"
}

usage() {
cat <<_EOF
  Usage: $(basename "$0") [options]
    options:
      -i|--input <file> : Input Vdex file to repair location checksum(s) within
      -a|--app <file>   : Input Apk file to extract location checksum(s) from
      -o|--output <dir> : Directory to save updated Vdex file (default is '.')
      -h|--help         : This help message
_EOF
  abort 1
}

commandExists() {
  type "$1" &> /dev/null
}

trap "abort 1" SIGHUP SIGINT SIGTERM

INPUT_VDEX=""
INPUT_BC=""
OUTPUT_DIR="$(pwd)"

for i in "${SYS_TOOLS[@]}"
do
  if ! commandExists "$i"; then
    error "'$i' command not found"
    abort 1
  fi
done

while [[ $# -gt 0 ]]
do
  arg="$1"
  case $arg in
    -o|--output)
      OUTPUT_DIR="$2"
      shift
      ;;
    -i|--input)
      INPUT_VDEX="$2"
      shift
      ;;
    -a|--app)
      INPUT_BC="$2"
      shift
      ;;
    -h|--help)
      usage
      ;;
    *)
      error "Invalid argument '$1'"
      usage
      ;;
  esac
  shift
done

if [[ "$INPUT_VDEX" == "" || "$INPUT_BC" == "" ]]; then
  error "Missing input arguments"
  usage
fi

checksumsFile="$TMP_WORK_DIR/checksums.txt"
unzip -vl "$INPUT_BC" | grep "dex$" | sed 's/  */ /g' | cut -d " " -f8 > "$checksumsFile" || {
  error "Input bytecode source if not a Zip archive"
}

# TODO: Add support for Dex CRC extraction

$VDEX_EXTRACTOR_BIN -i "$INPUT_VDEX" -o "$OUTPUT_DIR" --new-crc "$checksumsFile" || {
  error "vdexExtractor execution failed"
  abort 1
}

abort 0
