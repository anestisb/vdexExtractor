#!/usr/bin/env bash

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

  "$NDK/ndk-build" clean
  "$NDK/ndk-build" || {
    echo "[-] android build failed"
    exit 1
  }

  find libs -mindepth 1 -maxdepth 1 -type d | while read -r cpuBaseDir
  do
    cpu=$(basename "$cpuBaseDir")
    cp libs/"$cpu"/"$MODULE_NAME" bin/"$MODULE_NAME"-"$cpu"
  done
}

function build()
{
  local compiler="$1"

  make clean -C src || {
    echo "[-] make clean failed"
    exit 1
  }

  CC=$compiler make -C src || {
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

case "$target" in
  "") build "gcc";;
  "gcc") build "gcc";;
  "clang") build "clang";;
  "cross-android") build_cross_android;;
  "clean") clean;;
  *) usage;;
esac

exit 0
