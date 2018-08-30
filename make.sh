#!/usr/bin/env bash
#
# vdexExtractor
# -----------------------------------------
#
# Anestis Bechtsoudis <anestis@census-labs.com>
# Copyright 2017 by CENSUS S.A. All Rights Reserved.
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

declare -a sysTools=( "make" )

readonly MODULE_NAME="vdexExtractor"

function commandExists()
{
  type "$1" &> /dev/null
}

function usage()
{
  echo "$(basename "$0") [gcc|clang|cross-android|clean] (default is gcc)"
  exit 1
}

function build_cross_android()
{
  local cpu cpuBaseDir
  if [[ -z ${NDK+x} ]]; then
    # Search in $PATH
    if [[ $(which ndk-build) != "" ]]; then
      NDK=$(dirname "$(which ndk-build)")
    else
      echo "[-] Could not detect Android NDK dir"
      exit 1
    fi
  fi

  local ndk_extra_args=""
  if [ "$DEBUG_BUILD" = true ]; then
    ndk_extra_args+="V=1 NDK_DEBUG=1 APP_OPTIM=debug"
  fi

  "$NDK/ndk-build" clean
  "$NDK/ndk-build" $ndk_extra_args || {
    echo "[-] android build failed"
    exit 1
  }

  local baseDir=libs
  if [ "$DEBUG_BUILD" = true ]; then
    baseDir=obj/local
  fi

  find libs -mindepth 1 -maxdepth 1 -type d | while read -r cpuBaseDir
  do
    cpu=$(basename "$cpuBaseDir")
    cp "$baseDir/$cpu/$MODULE_NAME" "bin/$MODULE_NAME-android-$cpu"
  done
}

function build()
{
  local compiler="$1"
  if [[ "$compiler" == "" ]]; then
    if [[ -z ${CC+x} || "$CC" == "" ]]; then
      compiler="gcc"
    else
      compiler="$CC"
    fi
  fi

  make clean -C src || {
    echo "[-] make clean failed"
    exit 1
  }

  CC=$compiler DEBUG=$DEBUG_BUILD make -C src || {
    echo "[-] build failed"
    exit 1
  }
}

function clean()
{
  make clean -C src || {
    echo "[-] make clean failed"
    exit 1
  }

  if [[ -z ${NDK+x} ]]; then
    # Search in $PATH
    if [[ $(which ndk-build) != "" ]]; then
      NDK=$(dirname "$(which ndk-build)")
      "$NDK/ndk-build" clean
    fi
  fi
}

# Check that common system tools exist
for i in "${sysTools[@]}"
do
  if ! commandExists "$i"; then
    echo "[-] '$i' command not found"
    exit 1
  fi
done

if [ $# -gt 1 ]; then
  echo "[-] Invalid args"
  exit 1
fi

if [ $# -eq 0 ]; then
  target=""
else
  target="$1"
fi

if [[ -z ${DEBUG+x} || $DEBUG != true ]]; then
  DEBUG_BUILD=false
else
  DEBUG_BUILD=true
fi

case "$target" in
  "") build "";;
  "gcc") build "gcc";;
  "clang") build "clang";;
  "cross-android") build_cross_android;;
  "clean") clean;;
  *) usage;;
esac

exit 0
