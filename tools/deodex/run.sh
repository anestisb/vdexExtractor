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
# set -x # debug

readonly TOOL_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
readonly CONSTS_SCRIPT="$TOOL_ROOT/constants.sh"
readonly VDEX_EXTRACTOR_BIN="$TOOL_ROOT/../../bin/vdexExtractor"

declare -a SYS_TOOLS=("mkdir" "dirname" "wget" "shasum" "unzip")
readonly HOST_OS="$(uname -s)"

info()   { echo -e  "[INFO]: $*" 1>&2; }
warn()   { echo -e  "[WARN]: $*" 1>&2; }
error()  { echo -e  "[ERR ]: $*" 1>&2; }
debug()  { echo -e  "[DBG ]: $*" 1>&2; }
log()    { echo -e  "        $*" 1>&2; }
userIn() { echo -en "[IN  ]: $*" 1>&2; }

abort() {
  exit "$1"
}

usage() {
cat <<_EOF
  Usage: $(basename "$0") [options]
    options:
      -i|--input <path> : Directory with Vdex files or single file
      -o|--output <dir> : Directory to save deodex'ed resources (default is '.')
      -k|--keep         : Keep intermediate files (default 'false')
      -h|--help         : This help message
_EOF
  abort 1
}

commandExists() {
  type "$1" &> /dev/null
}

deps_download() {
  local api_level="$1"

  local download_url
  local out_file="$TOOL_ROOT/hostTools/$HOST_OS/api-$api_level/deps.zip"
  mkdir -p "$(dirname "$out_file")"


  if [[ "$HOST_OS" == "Darwin" ]]; then
    download_url="D_DEPS_URL_$api_level"
  else
    download_url="L_DEPS_URL_$api_level"
  fi

  wget -O "$out_file" "${!download_url}" || {
    echo "dependencies download failed"
    abort 1
  }

  unzip -qq -o "$out_file" -d "$TOOL_ROOT/hostTools/$HOST_OS/api-$api_level" || {
    echo "dependencies unzip failed"
    abort 1
  }
}

needs_deps_update() {
  local api_level="$1"
  local deps_zip deps_cur_sig deps_latest_sig

  deps_zip="$TOOL_ROOT/hostTools/$HOST_OS/api-$api_level/deps.zip"
  deps_cur_sig=$(shasum -a256 "$deps_zip" | cut -d ' ' -f1)
  if [[ "$HOST_OS" == "Darwin" ]]; then
    deps_latest_sig="D_DEPS_$api_level""_SIG"
  else
    deps_latest_sig="L_DEPS_$api_level""_SIG"
  fi

  if [[ "${!deps_latest_sig}" == "$deps_cur_sig" ]]; then
    return 1
  else
    return 0
  fi
}

deps_prepare_env() {
  local api_level="$1"
  if [ ! -f "$TOOL_ROOT/hostTools/$HOST_OS/api-$api_level/bin/compact_dex_converter" ]; then
    echo "First run detected - downloading compact_dex_converter bin & lib dependencies"
    deps_download "$api_level"
  fi

  if needs_deps_update "$api_level"; then
    echo "Outdated version detected - downloading compact_dex_converter bin & lib dependencies"
    deps_download "$api_level"
  fi
}

trap "abort 1" SIGINT SIGTERM
. "$CONSTS_SCRIPT"

INPUT_DIR=""
OUTPUT_DIR="$(pwd)"
KEEP_TMP=false

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
      INPUT_DIR="$2"
      shift
      ;;
    -k|--keep)
      KEEP_TMP=true
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

if [[ "$INPUT_DIR" == "" ]]; then
  error "Missing input directory"
  usage
fi

# Prepare output directory
if [ ! -d "$OUTPUT_DIR" ]; then
  mkdir -p "$OUTPUT_DIR" || {
    error "Failed to create output directory"
    abort 1
  }
fi

# Intermediate files as exported from vdexExtractor
decompiled_output="$OUTPUT_DIR/vdexExtractor_decompiled"
mkdir -p "$decompiled_output"
rm -rf "${decompiled_output:?}"/*

# Final output
deodexed_output="$OUTPUT_DIR/vdexExtractor_deodexed"
mkdir -p "$deodexed_output"
rm -rf "${deodexed_output:?}"/*

# Check if tool found
if [ ! -f "$VDEX_EXTRACTOR_BIN" ]; then
  error "vdexExtractor binary not found in '$VDEX_EXTRACTOR_BIN'"
  abort 1
fi

vdexFound=$(find "$INPUT_DIR" -type f -name "*.vdex" | wc -l | tr -d ' ')
info "Processing $vdexFound input Vdex files"

# Manually iterate input since we want to take API-level decisions while also supporting reading
# mixed-API files in same input
find "$INPUT_DIR" -name "*.vdex" | while read -r file
do
  binName=$(basename "$file" ".vdex")
  outDecBase="$decompiled_output/$binName"
  outDec="$outDecBase/decompiled"
  mkdir -p "$outDec"
  decLog="$outDecBase/dec_log.txt"
  convLog="$outDecBase/conv_log.txt"

  outDeodexBase="$deodexed_output/$binName"
  mkdir -p "$outDeodexBase"

  $VDEX_EXTRACTOR_BIN -i "$file" -o "$outDec" --ignore-crc-error &> "$decLog" || {
    error "vdexExtractor execution failed"
    cat "$decLog"
    abort 1
  }

  dexFound=0
  dexFound=$(find "$outDec" -type f -name "*.dex" | wc -l | tr -d ' ')
  if [ "$dexFound" -eq 0 ]; then
    dexFound=$(find "$outDec" -type f -name "*.cdex" | wc -l | tr -d ' ')
    if [ "$dexFound" -eq 0 ]; then
      warn "Skipping '$binName' since no decompiled resources found"
      rm -rf "$outDeodexBase"
      continue
    fi
    # If CompactDex files, we need to convert first to standard Dex
    # First detect the API level
    apiLevel=$($VDEX_EXTRACTOR_BIN --get-api -i "$file" || echo "")
    if ! echo "$apiLevel" | grep -qoE 'API-[0-9]{1,2}'; then
      echo "Invalid Android API level '$apiLevel'"
      abort 1
    fi
    apiLevel=$(echo "${apiLevel//-/_}")

    # Then check if the corresponding precompiled hostUtils have been downloaded
    deps_prepare_env "$apiLevel"
    cdexConvBin="$TOOL_ROOT/hostTools/$HOST_OS/api-$apiLevel/bin/compact_dex_converter"

    # Then convert each CompactDex file
    cdexFiles=($(find "$outDec" -type f -name "*.cdex"))
    $cdexConvBin -w "$outDeodexBase" "${cdexFiles[@]}" &> "$convLog" || {
      error "CompactDex conversation failed for '$file'"
      cat "$convLog"
      abort 1
    }

    # Finally change file extension to dex
    find "$outDeodexBase" -type f | while read -r cdexFile
    do
      fileName=$(basename "$cdexFile" .cdex)
      mv "$cdexFile" "$outDeodexBase/$fileName.dex"
    done
  else
    # If StandardDex files, copy as is since they're fully deodexed
    cp "$outDec"/* "$outDeodexBase"/
  fi
done

appsDeodexed=$(find "$deodexed_output" -maxdepth 1 ! -path "$deodexed_output" -type d | wc -l | tr -d ' ')
info "$appsDeodexed binaries have been successfully deodexed"

if [ $KEEP_TMP = false ]; then
  rm -rf "$decompiled_output"
fi

abort 0
