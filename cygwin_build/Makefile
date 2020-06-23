# Makefile
# Copyright (C) 2020 Feng Shun.
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License version 2 as 
#   published by the Free Software Foundation, either version 3 of the
#   License, or (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License version 2 for more details.
#
#   You should have received a copy of the GNU General Public License
#   version 2 along with this program. If not, see
#   <http://www.gnu.org/licenses/>.

SRC_PREFIX = ../src/
INCLUDE_DIR_CFLAGS = -I../include/ -I../uthash/src -I../minhook/include
LIB_DIR_LDFLAGS = -L../minhook/

DLL_SRCS = $(sort $(sort $(wildcard $(SRC_PREFIX)dll/*.c)))
DLL_OBJS = $(patsubst $(SRC_PREFIX)%,%,$(DLL_SRCS:.c=.o))

NONDLL_SRCS = $(sort $(wildcard $(SRC_PREFIX)cygwin_strsafe/*.c)) $(sort $(wildcard $(SRC_PREFIX)exe/*.c)) $(sort $(wildcard $(SRC_PREFIX)*.c))
NONDLL_OBJS = $(patsubst $(SRC_PREFIX)%,%,$(NONDLL_SRCS:.c=.o))

SRCS = $(DLL_SRCS) $(NONDLL_SRCS)
OBJS = $(patsubst $(SRC_PREFIX)%,%,$(SRCS:.c=.o))

DEPS = $(patsubst $(SRC_PREFIX)%,%,$(SRCS:.c=.d))

CFLAGS = -fno-omit-frame-pointer -fno-strict-aliasing -fgnu89-inline -Wall -D_UNICODE -DUNICODE $(INCLUDE_DIR_CFLAGS)
DLL_CFLAGS = $(CFLAGS) -DPXCH_DLL_EXPORTS

DEPFLAGS_STEM = -MT $@ -MMD -MP -MF $*.d
DEPFLAGS_IN_PREREQ = -MT $@ -MMD -MP -MF $(filter %.d,$^)

ifeq ($(shell getconf LONG_BIT),64)
ARCHITECT = x64
else
ARCHITECT = x86
endif

ifeq ($(shell uname -o),Cygwin)
CYGWIN_LIB = cygwin
CYGWIN_DLL_PREFIX = cyg
CYGWIN_EXEC_OS_DESC = cygwin
else
CYGWIN_LIB = msys-2.0
#CFLAGS += -DPXCH_MSYS_USE_WIN32_STYLE
CFLAGS += -DPXCH_IS_MSYS
DLL_CFLAGS += -DPXCH_IS_MSYS
CYGWIN_DLL_PREFIX = msys-
CYGWIN_EXEC_OS_DESC = msys
endif

EXEC_PATH_DEBUG = ./proxychains_$(CYGWIN_EXEC_OS_DESC)_$(ARCHITECT)d.exe
EXEC_PATH_RELEASE = ./proxychains_$(CYGWIN_EXEC_OS_DESC)_$(ARCHITECT).exe
HELPER_PATH_DEBUG = ./proxychains_helper_$(CYGWIN_EXEC_OS_DESC)_$(ARCHITECT)d.exe
HELPER_PATH_RELEASE = ./proxychains_helper_$(CYGWIN_EXEC_OS_DESC)_$(ARCHITECT).exe
REMOTE_FUNC_BIN_HEADER_DEBUG = ../include/remote_func_bin_$(ARCHITECT)d.h
REMOTE_FUNC_BIN_HEADER_RELEASE = ../include/remote_func_bin_$(ARCHITECT).h

DLL_MODULE_NAME_DEBUG = proxychains_hook_$(ARCHITECT)d
DLL_MODULE_NAME_RELEASE = proxychains_hook_$(ARCHITECT)

DLL_NAME_DEBUG = $(CYGWIN_DLL_PREFIX)$(DLL_MODULE_NAME_DEBUG)
DLL_NAME_RELEASE = $(CYGWIN_DLL_PREFIX)$(DLL_MODULE_NAME_RELEASE)
DLL_PATH_DEBUG = ./$(DLL_NAME_DEBUG).dll
DLL_PATH_RELEASE = ./$(DLL_NAME_RELEASE).dll
DLL_IMPLIB_PATH_DEBUG = ./lib$(DLL_MODULE_NAME_DEBUG).a
DLL_IMPLIB_PATH_RELEASE = ./lib$(DLL_MODULE_NAME_RELEASE).a

ALL_IMPLIBS_DEBUG = $(DLL_IMPLIB_PATH_DEBUG)
ALL_SHARED_LIBS_DEBUG = $(DLL_PATH_DEBUG)
ALL_EXECS_DEBUG = $(EXEC_PATH_DEBUG)

ALL_IMPLIBS_RELEASE = $(DLL_IMPLIB_PATH_RELEASE)
ALL_SHARED_LIBS_RELEASE = $(DLL_PATH_RELEASE)
ALL_EXECS_RELEASE = $(EXEC_PATH_RELEASE)

MAKE_DIR_1 := $(shell [ -d dll ] || mkdir -p dll)
MAKE_DIR_2 := $(shell [ -d exe ] || mkdir -p exe)
MAKE_DIR_3 := $(shell [ -d cygwin_strsafe ] || mkdir -p cygwin_strsafe)

MAKEFILE_PATH = $(abspath $(firstword $(MAKEFILE_LIST)))
MAKEFILE_DIR = $(dir $(MAKEFILE_PATH))

ifeq ($(DEBUG),0)

all : release
	@echo Made release

else
ifndef DEBUG

all : release
	@echo Made release
	
else

all : debug
	@echo Made debug
	
endif
endif

debug : CFLAGS += -g -DDEBUG -D_DEBUG
debug : DLL_CFLAGS += -g -DDEBUG -D_DEBUG
debug : pre_debug $(ALL_EXECS_DEBUG)

release : CFLAGS += -O2
release : DLL_CFLAGS += -O2
release : pre_release $(ALL_EXECS_RELEASE)

pre_debug : MAKING_DEBUG MAKING_$(ARCHITECT) $(REMOTE_FUNC_BIN_HEADER_DEBUG)
	$(eval REMOTE_FUNC_BIN_HEADER := $(REMOTE_FUNC_BIN_HEADER_DEBUG))

pre_release : MAKING_RELEASE MAKING_$(ARCHITECT) $(REMOTE_FUNC_BIN_HEADER_RELEASE)
	$(eval REMOTE_FUNC_BIN_HEADER := $(REMOTE_FUNC_BIN_HEADER_RELEASE))

MAKING_DEBUG :
	$(MAKE) -f $(MAKEFILE_PATH) clean_include_profile_mark
	touch MAKING_DEBUG
	
MAKING_RELEASE :
	$(MAKE) -f $(MAKEFILE_PATH) clean_include_profile_mark
	touch MAKING_RELEASE

MAKING_x64 :
	$(MAKE) -f $(MAKEFILE_PATH) clean_include_arch_mark
	touch MAKING_x64
	
MAKING_x86 :
	$(MAKE) -f $(MAKEFILE_PATH) clean_include_arch_mark
	touch MAKING_x86

$(NONDLL_OBJS) : %.o : $(SRC_PREFIX)%.c %.d
	$(CC) $(CFLAGS) $(DEPFLAGS_STEM) -c -o$@ $<
	
$(DLL_OBJS) : %.o : $(SRC_PREFIX)%.c %.d
	$(CC) $(DLL_CFLAGS) $(DEPFLAGS_STEM) -c -o$@ $<

$(DEPS) : 
	
$(HELPER_PATH_DEBUG) : proxychains_helper.o $(SRC_PREFIX)remote_function.c remote_function.d
	$(CC) $(filter-out -O2,$(CFLAGS)) -g $(DEPFLAGS_IN_PREREQ) -O0 -c -oremote_function.o $(SRC_PREFIX)remote_function.c
	$(CC) -o$@ $(filter %.o %.a %.lib,$^) remote_function.o -Wl,-Bdynamic -lntdllcrt -lkernel32 -l$(CYGWIN_LIB)

$(HELPER_PATH_RELEASE) : proxychains_helper.o $(SRC_PREFIX)remote_function.c remote_function.d
	$(CC) $(filter-out -O2,$(CFLAGS)) -g $(DEPFLAGS_IN_PREREQ) -O0 -c -oremote_function.o $(SRC_PREFIX)remote_function.c
	$(CC) -o$@ $(filter %.o %.a %.lib,$^) remote_function.o -Wl,-Bdynamic -lntdllcrt -lkernel32 -l$(CYGWIN_LIB)

$(REMOTE_FUNC_BIN_HEADER_DEBUG) : $(HELPER_PATH_DEBUG)
	$(HELPER_PATH_DEBUG) --dump-functions > $@

$(REMOTE_FUNC_BIN_HEADER_RELEASE) : $(HELPER_PATH_RELEASE)
	$(HELPER_PATH_RELEASE) --dump-functions > $@
	
dll/hookdll_main.o : MADE_REMOTE_FUNC_BIN_HEADER

MADE_REMOTE_FUNC_BIN_HEADER : proxychains_helper.o $(SRC_PREFIX)remote_function.c
	$(MAKE) -f $(MAKEFILE_PATH) $(REMOTE_FUNC_BIN_HEADER)
	touch MADE_REMOTE_FUNC_BIN_HEADER
	
$(DLL_PATH_DEBUG) : ../minhook/libMinHook.a dll/hookdll_main.o dll/hook_connect_win32.o dll/hook_connect_win32.o dll/hook_connect_cygwin.o dll/hook_createprocess_win32.o dll/hook_installer.o dll/ipc_client_and_child_data.o dll/hookdll_util_log_win32.o dll/hookdll_util_log_cygwin.o dll/hookdll_util_wsock_win32.o dll/hookdll_util_ipc_message_win32.o cygwin_strsafe/strsafe.o
	$(CC) -shared -o$@ -Wl,--out-implib=$(DLL_IMPLIB_PATH_DEBUG),--output-def,$@.def $(LIB_DIR_LDFLAGS) $(filter %.o %.a %.lib,$^) -Wl,-static -lMinHook -Wl,-Bdynamic -lntdllcrt -lws2_32 -lshlwapi
	
$(DLL_PATH_RELEASE) : ../minhook/libMinHook.a dll/hookdll_main.o dll/hook_connect_win32.o dll/hook_connect_win32.o dll/hook_connect_cygwin.o dll/hook_createprocess_win32.o dll/hook_installer.o dll/ipc_client_and_child_data.o dll/hookdll_util_log_win32.o dll/hookdll_util_log_cygwin.o dll/hookdll_util_wsock_win32.o dll/hookdll_util_ipc_message_win32.o cygwin_strsafe/strsafe.o
	$(CC) -shared -o$@ -Wl,--out-implib=$(DLL_IMPLIB_PATH_RELEASE),--output-def,$@.def $(LIB_DIR_LDFLAGS) $(filter %.o %.a %.lib,$^) -Wl,-static -lMinHook -Wl,-Bdynamic -lntdllcrt -lws2_32 -lshlwapi

#	-Wl,--export-all-symbols \
#	-Wl,--enable-auto-import \
	
$(DLL_IMPLIB_PATH_DEBUG) : $(DLL_PATH_DEBUG)
$(DLL_IMPLIB_PATH_RELEASE) : $(DLL_PATH_RELEASE)

$(EXEC_PATH_DEBUG) : ../minhook/libMinHook.a exe/main.o exe/args_and_config.o exe/ipc_proc_bookkeeping.o stdlib_config_reader.o cygwin_strsafe/strsafe.o $(DLL_IMPLIB_PATH_DEBUG)
	$(CC) -o$@ $(filter %.o %.a %.lib,$^) $(LIB_DIR_LDFLAGS) -Wl,-static -lMinHook -Wl,-Bdynamic -lntdllcrt -lkernel32 -lshlwapi -ladvapi32 -l$(CYGWIN_LIB) -lws2_32
	
$(EXEC_PATH_RELEASE) : ../minhook/libMinHook.a exe/main.o exe/args_and_config.o exe/ipc_proc_bookkeeping.o stdlib_config_reader.o cygwin_strsafe/strsafe.o $(DLL_IMPLIB_PATH_RELEASE)
	$(CC) -o$@ $(filter %.o %.a %.lib,$^) $(LIB_DIR_LDFLAGS) -Wl,-static -lMinHook -Wl,-Bdynamic -lntdllcrt -lkernel32 -lshlwapi -ladvapi32 -l$(CYGWIN_LIB) -lws2_32

.PHONY : clean_except_mark clean_include_profile_mark clean_include_arch_mark clean dist pre_debug pre_release

clean_except_mark :
	$(RM) MADE_REMOTE_FUNC_BIN_HEADER
	$(RM) $(ALL_EXECS_DEBUG) $(ALL_EXECS_RELEASE)
	$(RM) $(ALL_SHARED_LIBS_DEBUG) $(ALL_SHARED_LIBS_RELEASE)
	$(RM) $(ALL_SHARED_LIBS_DEBUG).def $(ALL_SHARED_LIBS_RELEASE).def
	$(RM) $(ALL_IMPLIBS_DEBUG) $(ALL_IMPLIBS_RELEASE)
	$(RM) $(OBJS)
	$(RM) $(DEPS)
	$(RM) $(HELPER_PATH_DEBUG) $(HELPER_PATH_RELEASE)
	$(RM) $(REMOTE_FUNC_BIN_HEADER_DEBUG) $(REMOTE_FUNC_BIN_HEADER_RELEASE)
	$(MAKE) -C ../minhook -f ../minhook/build/MinGW/Makefile clean

clean_include_profile_mark : clean_except_mark
	$(RM) MAKING_DEBUG MAKING_RELEASE

clean_include_arch_mark : clean_except_mark
	$(RM) MAKING_x86 MAKING_x64

clean : clean_except_mark
	$(RM) MAKING_*

../minhook/libMinHook.a :
	$(MAKE) -C ../minhook -f ../minhook/build/MinGW/Makefile

install : release
	cp $(EXEC_PATH_RELEASE) $(PREFIX)/bin/proxychains.exe
	cp $(EXEC_PATH_RELEASE) $(PREFIX)/bin/px.exe
	cp $(DLL_PATH_RELEASE) $(PREFIX)/bin/
	cp $(HELPER_PATH_RELEASE) $(PREFIX)/bin/

installd : debug
	cp $(EXEC_PATH_DEBUG) $(PREFIX)/bin/proxychainsd.exe
	cp $(EXEC_PATH_DEBUG) $(PREFIX)/bin/pxd.exe
	cp $(DLL_PATH_DEBUG) $(PREFIX)/bin/
	cp $(HELPER_PATH_DEBUG) $(PREFIX)/bin/

d :
	PXCH_VERSION=$$(gcc -dM -E - < ../include/version.h | grep PXCH_VERSION | sort | awk '{print $$3}' | head -c -1 | tr '\n' '.') $(MAKEFILE_DIR)dist.sh --win32 --cygwin
	
di :
	PXCH_VERSION=$$(gcc -dM -E - < ../include/version.h | grep PXCH_VERSION | sort | awk '{print $$3}' | head -c -1 | tr '\n' '.') $(MAKEFILE_DIR)dist.sh --win32 --cygwin --install

wd :
	PXCH_VERSION=$$(gcc -dM -E - < ../include/version.h | grep PXCH_VERSION | sort | awk '{print $$3}' | head -c -1 | tr '\n' '.') $(MAKEFILE_DIR)dist.sh --win32
	
wdi :
	PXCH_VERSION=$$(gcc -dM -E - < ../include/version.h | grep PXCH_VERSION | sort | awk '{print $$3}' | head -c -1 | tr '\n' '.') $(MAKEFILE_DIR)dist.sh --win32 --install

cd :
	PXCH_VERSION=$$(gcc -dM -E - < ../include/version.h | grep PXCH_VERSION | sort | awk '{print $$3}' | head -c -1 | tr '\n' '.') $(MAKEFILE_DIR)dist.sh --cygwin
	
cdi :
	PXCH_VERSION=$$(gcc -dM -E - < ../include/version.h | grep PXCH_VERSION | sort | awk '{print $$3}' | head -c -1 | tr '\n' '.') $(MAKEFILE_DIR)dist.sh --cygwin --install
	
distinstall_legacy:
	$(MAKE) -f $(MAKEFILE_PATH) release
	cp $(EXEC_PATH_RELEASE) $(PREFIX)/bin/proxychains.exe
	cp $(EXEC_PATH_RELEASE) $(PREFIX)/bin/px.exe
	cp $(DLL_PATH_RELEASE) $(PREFIX)/bin/
	cp $(HELPER_PATH_RELEASE) $(PREFIX)/bin/
	
	$(MAKE) -f $(MAKEFILE_PATH) debug
	cp $(EXEC_PATH_DEBUG) $(PREFIX)/bin/proxychainsd.exe
	cp $(EXEC_PATH_DEBUG) $(PREFIX)/bin/pxd.exe
	cp $(DLL_PATH_DEBUG) $(PREFIX)/bin/
	cp $(HELPER_PATH_DEBUG) $(PREFIX)/bin/
	
	
rebuild : clean all
rebuildrelease : clean release
rebuilddebug : clean debug

include $(wildcard $(DEPS))
