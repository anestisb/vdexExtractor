#   vdexExtractor
#   -----------------------------------------
#
#   Anestis Bechtsoudis <anestis@census-labs.com>
#   Copyright 2017 by CENSUS S.A. All Rights Reserved.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

LOCAL_PATH := $(call my-dir)

# Main module
include $(CLEAR_VARS)
LOCAL_MODULE    := vdexExtractor
SRC             := ../src
LOCAL_SRC_FILES := $(SRC)/log.c \
                   $(SRC)/utils.c \
                   $(SRC)/sha1.c \
                   $(SRC)/dex.c \
                   $(SRC)/dex_instruction.c \
                   $(SRC)/dex_decompiler.c \
                   $(SRC)/vdex.c \
                   $(SRC)/vdexExtractor.c
LOCAL_CFLAGS    += -c -std=c11 -D_GNU_SOURCE \
                   -Wall -Wextra -Werror
LOCAL_LDFLAGS   += -lm -lz
include $(BUILD_EXECUTABLE)
