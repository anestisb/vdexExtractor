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
SRC_FILE_LIST   := $(sort $(wildcard $(LOCAL_PATH)/$(SRC)/*.c)) $(sort $(wildcard $(LOCAL_PATH)/$(SRC)/*/*.c))
LOCAL_SRC_FILES := $(SRC_FILE_LIST:$(LOCAL_PATH)/%=%)
LOCAL_CFLAGS    += -c -std=c11 -D_GNU_SOURCE \
                   -Wall -Wextra -Werror
LOCAL_LDFLAGS   += -lm -lz

GIT_VERSION := $(shell git rev-parse --short HEAD | tr -d "\n")
LOCAL_CFLAGS += -DVERSION=\"dev-$(GIT_VERSION)\"

include $(BUILD_EXECUTABLE)
