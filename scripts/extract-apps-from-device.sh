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

declare -ar SYS_TOOLS=("mkdir" "dirname" "sed" "grep" "adb")
declare -ar ART_FILE_FORMATS=("art" "dex" "vdex" "odex")

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
      -o|--output <dir>  : Output directory to save extracted data (default is '.')
      -d|--device <devID>: Device serial to use instead of default interactive selection
      --system-apps      : Extract system apps too (default is user apps only)
      --apks             : Extract apks (default is optimized files only)
      -h|--help          : This help message
_EOF
  abort 1
}

commandExists() {
  type "$1" &> /dev/null
}

arrayHasStr() {
  local element
  for element in "${@:2}"; do [[ "$element" == "$1" ]] && return 0; done
  return 1
}

isDevAuthorized() {
  local serial="$1"

  if "$ADB_BIN" -s "$serial" shell id 2>&1 | grep -iq 'device unauthorized'; then
    return 1
  else
    return 0
  fi
}

getDevFingerprint() {
  local serial="$1"

  "$ADB_BIN" -s "$serial" shell "getprop ro.build.fingerprint" | tr -d '\r' || {
    error "Failed to extract Android device fingerprint"
    abort 1
  }
}

getDevSupportedISAs() {
  local serial="$1"

  local -a abiList=()
  IFS=',' read -r -a abiList <<< "$(getDevCpuAbiList "$serial")"
  (
   for abi in "${abiList[@]}"; do getFormattedISA "$abi"; done
  ) | uniq | tr '\n' ' '
}

getFormattedISA() {
  case $1 in
  armeabi|armeabi-v7a)
    echo "arm"
    ;;
  arm64-v8a)
    echo "arm64"
    ;;
  x86)
    echo "x86"
    ;;
  x86-64)
    echo "x86-64"
    ;;
  *)
    error "Invalid CPU ABI '$1'"
    usage
    ;;
  esac
}

getDevCpuAbiList() {
  local serial="$1"

  "$ADB_BIN" -s "$serial" shell "getprop ro.product.cpu.abilist" | tr -d '\r' || {
    error "Failed to extract Android device fingerprint"
    abort 1
  }
}

getDevApi() {
  local serial="$1"

  "$ADB_BIN" -s "$serial" shell "getprop ro.build.version.sdk" | tr -d '\r' || {
    error "Failed to extract Android device fingerprint"
    abort 1
  }
}

getConnectedDevices() {
  # Ensure adb server is running
  local adbServerLog="$TMP_WORK_DIR/adb_start_server.log"
  "$ADB_BIN" start-server &> "$adbServerLog" || {
    error "Failed to start adb server"
    cat "$adbServerLog"
    abort 1
  }

  local devCount=0
  devCount=$("$ADB_BIN" devices -l | grep -v '^$' | grep -v "List of" -c || true)
  if [ "$devCount" == 0 ]; then
    warn "No connected Android devices found - verify devices are connected & discoverable"
    return
  fi

  # Change IFS to parse by line
  local oldIFS="$IFS"
  IFS=$'\n'

  DEVICES_ARRAY=( $("$ADB_BIN" devices -l | grep -v "List of" | cut -d ' ' -f1 || true) )

  # Revert IFS
  IFS="$oldIFS"
}

processConnectedDevices() {
  info "Enumerating connected Android devices"
  getConnectedDevices

  # if no user selected device switch to interactive selection
  if [[ "$TARGET_DEVICE" == "" ]]; then
    if [[ ${#DEVICES_ARRAY[@]} -gt 0 ]]; then
      local devArrOff=0
      # Prompt user for choice if more than one connected devices
      if [[ ${#DEVICES_ARRAY[@]} -gt 1 ]]; then
        for (( i=0; i<${#DEVICES_ARRAY[@]}; i++ ))
        do
          local curDevFingerprint=""
          if isDevAuthorized "${DEVICES_ARRAY[i]}"; then
            curDevFingerprint=$(getDevFingerprint "${DEVICES_ARRAY[i]}")
            log "$i: ${DEVICES_ARRAY[i]} ($curDevFingerprint) [AUTH:true]"
          else
            log "$i: ${DEVICES_ARRAY[i]} [AUTH:false]"
          fi
        done
        if [[ ${#DEVICES_ARRAY[@]} -gt 1 ]]; then
          userIn "Enter device choice: "
          read devArrOff

          # Some error checking
          if [[ ! "$devArrOff" = *[[:digit:]]* ]]; then
            error "Invalid choice (not a number)"
            abort 1
          fi
          if [[ "$devArrOff" -ge ${#DEVICES_ARRAY[@]} || "$devArrOff" -lt 0 ]]; then
            error "Invalid choice (out of bounds)"
            abort 1
          fi
        fi
      fi
      TARGET_DEVICE=$(echo "${DEVICES_ARRAY[$devArrOff]}" | cut -d '"' -f2)
    fi
  else
    # Verify selected device is connected
    if ! arrayHasStr "$TARGET_DEVICE" "${DEVICES_ARRAY[@]}"; then
      error "Selected '$TARGET_DEVICE' device is not connected to host"
      abort 1
    fi
  fi

  if [[ "$TARGET_DEVICE" != "" ]]; then
    if ! isDevAuthorized "$TARGET_DEVICE"; then
      error "Cannot proceed with device '$TARGET_DEVICE' since it's not authorized"
      abort 1
    fi
  fi
}

remoteFileReadable() {
  local devSerial="$1"
  local remoteFile="$2"

  local adbFileCheckLog="$TMP_WORK_DIR/adb_file_check.log"

  "$ADB_BIN" -s "$targetDev" shell "if [ -r \"$remoteFile\" ]; then echo 'yes'; else echo 'no'; fi" | \
   tr -d '\r' > "$adbFileCheckLog" || {
    error "Failed to check file presence"
    abort 1
  }

  if [ "$(cat "$adbFileCheckLog")" == "yes" ]; then
    return 0;
  else
    return 1;
  fi
}

downloadFileOverAdb() {
  local devSerial="$1"
  local remoteFile="$2"
  local dstFile="$3"

  local adbDownLog="$TMP_WORK_DIR/adb_pull.log"

  # adb internally tries to list directory which is disallowed from selinux
  # for dalvikcache_data_file. As such copy first and then download.
  "$ADB_BIN" -s "$devSerial" shell "cp \"$remoteFile\" /data/local/tmp/temp.file" &> "$adbDownLog" || {
    error "Failed to copy temp file"
    cat "$adbDownLog"
    abort 1
  }

  "$ADB_BIN" -s "$devSerial" pull "/data/local/tmp/temp.file" "$dstFile" &> "$adbDownLog" || {
    if grep -q "Permission denied" "$adbDownLog"; then
      return;
    fi
    error "Failed to download file from device"
    cat "$adbDownLog"
    abort 1
  }

  "$ADB_BIN" -s "$devSerial" shell "rm /data/local/tmp/temp.file" &> "$adbDownLog" || {
    error "Failed to copy temp file"
    cat "$adbDownLog"
    abort 1
  }
}

extractInstalledApps() {
  local targetDev="$1"

  declare -a installed_apps=()
  declare -a installed_app_paths=()

  local appsList="$TMP_WORK_DIR/android_apps_list.txt"
  local appsFilter="" appPath=""

  if [[ "$EXTRACT_SYSTEM_APPS" = false ]]; then
    appsFilter="-3 -f"
  else
    appsFilter="-f"
  fi

  "$ADB_BIN" -s "$targetDev" shell "pm list packages $appsFilter" | \
   tr -d '\r' > "$appsList" || {
    error "Failed to extract installed applications list from device"
    abort 1
  }

  local package="" packageName="" packagePath=""
  while read -r package
  do
    packageName=$(echo "$package" | cut -d ':' -f2 | awk -F'.apk=' '{print $2}')
    packagePath=$(echo "$package" | cut -d ':' -f2 | awk -F'.apk=' '{print $1".apk"}')

    installed_apps+=("$packageName")
    installed_app_paths+=("$packagePath")
  done < <(cat "$appsList")

  if [ ${#installed_apps[@]} -eq 0 ]; then
    warn "No installed packages found"
    abort 0
  fi

  info "Trying to extract data from '${#installed_apps[@]}' packages"

  for (( i=0; i<${#installed_app_paths[@]}; i++ ))
  do
    local appPath="" remoteSrc="" localDst="" formatedBaseSuffix="" remoteSrcRoot=""
    appPath="${installed_app_paths[i]}"
    if [ "$EXTRACT_APKS" = true ]; then
      localDst="$OUTPUT_DIR/${installed_apps[i]}.apk"
      downloadFileOverAdb "$targetDev" "$appPath" "$localDst"
    fi

    if [[ "$appPath" == /data/app/* ]]; then
      formatedBaseSuffix="base"
      remoteSrcRoot="$(dirname "$appPath")/oat"
    else
      formatedBaseSuffix="$(echo "${appPath:1}" | tr / @)@classes"
      remoteSrcRoot="/data/dalvik-cache"
    fi
    for artFile in "${ART_FILE_FORMATS[@]}"
    do
      for abi in $(getDevSupportedISAs "$targetDev")
      do
        remoteSrc="$remoteSrcRoot/$abi/$formatedBaseSuffix.$artFile"
        if [[ "$artFile" == *dex ]]; then
          localDst="$OUTPUT_DIR/${installed_apps[i]}.$abi.oat"
        else
          localDst="$OUTPUT_DIR/${installed_apps[i]}.$abi.$artFile"
        fi
        if remoteFileReadable "$targetDev" "$remoteSrc"; then
          downloadFileOverAdb "$targetDev" "$remoteSrc" "$localDst"
        fi
      done
    done
  done
}

trap "abort 1" SIGHUP SIGINT SIGTERM

OUTPUT_DIR="$(pwd)"
EXTRACT_SYSTEM_APPS=false
EXTRACT_APKS=false
TARGET_DEVICE=""

declare -a DEVICES_ARRAY=()

for i in "${SYS_TOOLS[@]}"
do
  if ! commandExists "$i"; then
    error "'$i' command not found"
    abort 1
  fi
done

ADB_BIN="$(which adb)"

while [[ $# -gt 0 ]]
do
  arg="$1"
  case $arg in
    -o|--output)
      OUTPUT_DIR="$2"
      shift
      ;;
    -d|--device)
      TARGET_DEVICE="$2"
      shift
      ;;
    --system-apps)
      EXTRACT_SYSTEM_APPS=true
      ;;
    --apks)
      EXTRACT_APKS=true
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

processConnectedDevices

# Prepare output directory
if [ ! -d "$OUTPUT_DIR" ]; then
  mkdir -p "$OUTPUT_DIR" || {
    error "Failed to create output directory"
    abort 1
  }
fi

# Only releases >= Nougat are supported
apiVersion=$(getDevApi "$TARGET_DEVICE")
if [ "$apiVersion" -lt 24 ]; then
  error "Unsupported old API-$apiVersion"
  abort 1
fi

extractInstalledApps "$TARGET_DEVICE"

info "Extracted data stored under '$OUTPUT_DIR'"
abort 0
