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

DLL_SRCS = $(sort $(sort $(wildcard $(SRC_PREFIX)dll/*.c)) $(sort $(wildcard $(SRC_PREFIX)dll/remote_function/*.c)))
DLL_OBJS = $(patsubst $(SRC_PREFIX)%,%,$(DLL_SRCS:.c=.o))

NONDLL_SRCS = $(sort $(wildcard $(SRC_PREFIX)cygwin_strsafe/*.c)) $(sort $(wildcard $(SRC_PREFIX)exe/*.c)) $(sort $(wildcard $(SRC_PREFIX)*.c))
NONDLL_OBJS = $(patsubst $(SRC_PREFIX)%,%,$(NONDLL_SRCS:.c=.o))

SRCS = $(DLL_SRCS) $(NONDLL_SRCS)
OBJS = $(patsubst $(SRC_PREFIX)%,%,$(SRCS:.c=.o))

DEPS = $(patsubst $(SRC_PREFIX)%,%,$(SRCS:.c=.d))

CFLAGS = -fgnu89-inline -Wall -D_UNICODE -DUNICODE $(INCLUDE_DIR_CFLAGS)
DLL_CFLAGS = -fgnu89-inline -Wall -D_UNICODE -DUNICODE -DPXCH_DLL_EXPORTS $(INCLUDE_DIR_CFLAGS)

DEPFLAGS_STEM = -MT $@ -MMD -MP -MF $*.d
DEPFLAGS_IN_PREREQ = -MT $@ -MMD -MP -MF $(filter %.d,$^)

ifeq ($(shell getconf LONG_BIT),64)
ARCHITECT = x64
else
ARCHITECT = x86
endif

EXEC_PATH_DEBUG = ./proxychains_$(ARCHITECT)d.exe
EXEC_PATH_RELEASE = ./proxychains_$(ARCHITECT).exe
DLL_MODULE_NAME = proxychains_hook_$(ARCHITECT)

DLL_MODULE_NAME_DEBUG = $(DLL_MODULE_NAME)d
DLL_MODULE_NAME_RELEASE = $(DLL_MODULE_NAME)

DLL_NAME_DEBUG = cyg$(DLL_MODULE_NAME_DEBUG)
DLL_NAME_RELEASE = cyg$(DLL_MODULE_NAME_RELEASE)
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
MAKE_DIR_1 := $(shell [ -d dll/remote_function ] || mkdir -p dll/remote_function)
MAKE_DIR_2 := $(shell [ -d exe ] || mkdir -p exe)
MAKE_DIR_3 := $(shell [ -d cygwin_strsafe ] || mkdir -p cygwin_strsafe)

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
debug : MAKING_DEBUG $(ALL_EXECS_DEBUG)
	./$(EXEC_PATH_DEBUG) --dump-remote

release : CFLAGS += -DPXCH_LOG_LEVEL=400
release : DLL_CFLAGS += -DPXCH_LOG_LEVEL=400
release : MAKING_RELEASE $(ALL_EXECS_RELEASE)
	./$(EXEC_PATH_RELEASE) --dump-remote

MAKING_DEBUG :
	$(MAKE) clean
	touch MAKING_DEBUG
	
MAKING_RELEASE :
	$(MAKE) clean
	touch MAKING_RELEASE

$(NONDLL_OBJS) : %.o : $(SRC_PREFIX)%.c %.d
	$(CC) $(CFLAGS) $(DEPFLAGS_STEM) -c -o$@ $<
	
$(DLL_OBJS) : %.o : $(SRC_PREFIX)%.c %.d
	$(CC) $(DLL_CFLAGS) $(DEPFLAGS_STEM) -c -o$@ $<

$(DEPS) : 
	
configure.exe : configure.o
	$(CC) -o$@ configure.o -Wl,-Bdynamic -lntdllcrt -lkernel32 -lcygwin
    
../include/function_pointers_configured.h : configure.exe
	./configure.exe > ../include/function_pointers_configured.h
	
$(DLL_PATH_DEBUG) : ../minhook/libMinHook.a ../include/function_pointers_configured.h dll/dllmain.o dll/hook_connect_win32.o dll/hook_connect_win32.o dll/hook_connect_cygwin.o dll/hook_createprocess_win32.o dll/hook_installer.o dll/ipc_client_and_child_data.o dll/dllutil_log_func.o dll/dllutil_wsock.o dll/remote_function/remote_function.o common.o common_wsock.o ipc_message.o log.o cygwin_strsafe/strsafe.o
	$(CC) -shared -o$@ -Wl,--out-implib=$(DLL_IMPLIB_PATH_DEBUG) $(LIB_DIR_LDFLAGS) $(filter %.c %.o %.a %.lib,$^) -Wl,-static -lMinHook -Wl,-Bdynamic -lntdllcrt -lws2_32 -lshlwapi
	
$(DLL_PATH_RELEASE) : ../minhook/libMinHook.a ../include/function_pointers_configured.h dll/dllmain.o dll/hook_connect_win32.o dll/hook_connect_win32.o dll/hook_connect_cygwin.o dll/hook_createprocess_win32.o dll/hook_installer.o dll/ipc_client_and_child_data.o dll/dllutil_log_func.o dll/dllutil_wsock.o dll/remote_function/remote_function.o common.o common_wsock.o ipc_message.o log.o cygwin_strsafe/strsafe.o
	$(CC) -shared -o$@ -Wl,--out-implib=$(DLL_IMPLIB_PATH_RELEASE) $(LIB_DIR_LDFLAGS) $(filter %.c %.o %.a %.lib,$^) -Wl,-static -lMinHook -Wl,-Bdynamic -lntdllcrt -lws2_32 -lshlwapi
		
#	-Wl,--export-all-symbols \
#	-Wl,--enable-auto-import \
	
$(DLL_IMPLIB_PATH_DEBUG) : $(DLL_PATH_DEBUG)
$(DLL_IMPLIB_PATH_RELEASE) : $(DLL_PATH_RELEASE)

$(EXEC_PATH_DEBUG) : ../minhook/libMinHook.a exe/main.o exe/args_and_config.o exe/ipc_proc_bookkeeping.o stdlib_config_reader.o common.o common_wsock.o ipc_message.o log.o cygwin_strsafe/strsafe.o $(DLL_IMPLIB_PATH_DEBUG)
	$(CC) -o$@ $(filter %.c %.o %.a %.lib,$^) $(LIB_DIR_LDFLAGS) -Wl,-static -lMinHook -Wl,-Bdynamic -lntdllcrt -lkernel32 -lshlwapi -ladvapi32 -lcygwin -lws2_32
	
$(EXEC_PATH_RELEASE) : ../minhook/libMinHook.a exe/main.o exe/args_and_config.o exe/ipc_proc_bookkeeping.o stdlib_config_reader.o common.o common_wsock.o ipc_message.o log.o cygwin_strsafe/strsafe.o $(DLL_IMPLIB_PATH_RELEASE)
	$(CC) -o$@ $(filter %.c %.o %.a %.lib,$^) $(LIB_DIR_LDFLAGS) -Wl,-static -lMinHook -Wl,-Bdynamic -lntdllcrt -lkernel32 -lshlwapi -ladvapi32 -lcygwin -lws2_32

.PHONY : clean dist configure

clean :
	$(RM) MAKING_DEBUG MAKING_RELEASE
	$(RM) $(ALL_EXECS_DEBUG) $(ALL_EXECS_RELEASE)
	$(RM) $(ALL_SHARED_LIBS_DEBUG) $(ALL_SHARED_LIBS_RELEASE)
	$(RM) $(ALL_IMPLIBS_DEBUG) $(ALL_IMPLIBS_RELEASE)
	$(RM) $(OBJS)
	$(RM) $(DEPS)
	$(RM) ../include/function_pointers_configured.h configure.exe proxychains_remote_function_*.bin
	$(MAKE) -C ../minhook -f ../minhook/build/MinGW/Makefile clean

../minhook/libMinHook.a :
	$(MAKE) -C ../minhook -f ../minhook/build/MinGW/Makefile

dist :
	PXCH_VERSION=$$(gcc -dM -E - < ../include/version.h | grep PXCH_VERSION | sort | awk '{print $$3}' | head -c -1 | tr '\n' '.') ./dist.sh
	
distinstall :
	PXCH_VERSION=$$(gcc -dM -E - < ../include/version.h | grep PXCH_VERSION | sort | awk '{print $$3}' | head -c -1 | tr '\n' '.') ./dist.sh --install
	
distinstall_legacy:
	make release
	cp $(EXEC_PATH_RELEASE) $(PREFIX)/bin/proxychains.exe
	cp $(EXEC_PATH_RELEASE) $(PREFIX)/bin/px.exe
	cp $(DLL_PATH_RELEASE) $(PREFIX)/bin/
	cp proxychains_remote_function_*.bin $(PREFIX)/bin/
	
	make debug
	cp $(EXEC_PATH_DEBUG) $(PREFIX)/bin/proxychainsd.exe
	cp $(EXEC_PATH_DEBUG) $(PREFIX)/bin/pxd.exe
	cp $(DLL_PATH_DEBUG) $(PREFIX)/bin/
	cp proxychains_remote_function_*.bin $(PREFIX)/bin/
	
	
rebuild : clean all
rebuildrelease : clean release
rebuilddebug : clean debug

include $(wildcard $(DEPS))
