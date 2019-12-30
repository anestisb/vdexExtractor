#   vdexExtractor
#   -----------------------------------------
#
#   Anestis Bechtsoudis <anestis@census-labs.com>
#   Copyright 2017 - 2018 by CENSUS S.A. All Rights Reserved.
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

# Default to gcc
CC ?= gcc
DEBUG ?= false

TARGET  = vdexExtractor
CFLAGS  += -c -std=c11 -D_GNU_SOURCE \
           -Wall -Wextra -Werror
LDFLAGS += -lm -lz

ifeq ($(DEBUG),true)
  CFLAGS += -g -ggdb
  LDFLAGS += -g -ggdb
endif

LBITS := $(shell getconf LONG_BIT)
ifeq ($(LBITS),32)
  # If compiling in 32bit system
  CFLAGS += -Wno-pointer-to-int-cast
else
ifneq (,$(findstring -m32,$(CFLAGS)))
  # If cross-compiling for a 32bit target from a 64bit system
  CFLAGS += -Wno-pointer-to-int-cast
endif
endif

GIT_VERSION := $(shell git rev-parse --short HEAD | tr -d "\n")
CFLAGS += -DVERSION=\"dev-$(GIT_VERSION)\"

.PHONY: default all clean

default: $(TARGET)
all: default

OBJECTS = $(patsubst %.c, %.o, $(sort $(wildcard *.c)) $(sort $(wildcard */*.c)))
HEADERS = $(wildcard *.h)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) $(LDFLAGS) -o $@
	cp $(TARGET) ../bin/$(TARGET)

clean:
	-rm -f *.o
	-rm -f */*.o
	-rm -f $(TARGET)

format:
	clang-format-mp-9.0 -style="{BasedOnStyle: Google, \
    IndentWidth: 2, Cpp11BracedListStyle: false, \
    BinPackParameters: false, ColumnLimit: 100}" -i -sort-includes *.c *.h */*.c */*.h
