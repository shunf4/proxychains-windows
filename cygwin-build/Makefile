SRC_PREFIX = ../src/
INCLUDE_PREFIX = ../include/
LIB_PREFIX = ../lib/

DLL_SRCS = $(sort $(sort $(wildcard $(SRC_PREFIX)dll/*.c)) $(sort $(wildcard $(SRC_PREFIX)dll/remote_function/*.c)))
DLL_OBJS = $(patsubst $(SRC_PREFIX)%,%,$(DLL_SRCS:.c=.o))

NONDLL_SRCS = $(sort $(wildcard $(SRC_PREFIX)cygwin_strsafe/*.c)) $(sort $(wildcard $(SRC_PREFIX)exe/*.c)) $(sort $(wildcard $(SRC_PREFIX)*.c))
NONDLL_OBJS = $(patsubst $(SRC_PREFIX)%,%,$(NONDLL_SRCS:.c=.o))

SRCS = $(DLL_SRCS) $(NONDLL_SRCS)
OBJS = $(patsubst $(SRC_PREFIX)%,%,$(SRCS:.c=.o))

DEPS = $(patsubst $(SRC_PREFIX)%,%,$(SRCS:.c=.d))

CFLAGS = -fgnu89-inline -Wall -D_UNICODE -DUNICODE -I$(INCLUDE_PREFIX)
DLL_CFLAGS = -fgnu89-inline -Wall -D_UNICODE -DUNICODE -DPXCH_DLL_EXPORTS -I$(INCLUDE_PREFIX)

DEPFLAGS_STEM = -MT $@ -MMD -MP -MF $*.d
DEPFLAGS_IN_PREREQ = -MT $@ -MMD -MP -MF $(filter %.d,$^)

EXEC_PATH = ./proxychains.exe
DLL_MODULE_NAME = proxychains_hook
DLL_PATH = ./cyg$(DLL_MODULE_NAME).dll
DLL_IMPLIB_PATH = ./lib$(DLL_MODULE_NAME).a

ALL_IMPLIBS = $(DLL_IMPLIB_PATH)
ALL_SHARED_LIBS = $(DLL_PATH)
ALL_EXECS = $(EXEC_PATH)

all : release

debug : CFLAGS += -g -DDEBUG -D_DEBUG
debug : DLL_CFLAGS += -g -DDEBUG -D_DEBUG
debug : $(ALL_EXECS)

release : CFLAGS += -DPXCH_LOG_LEVEL=400
release : DLL_CFLAGS += -DPXCH_LOG_LEVEL=400
release : $(ALL_EXECS)

$(NONDLL_OBJS) : %.o : $(SRC_PREFIX)%.c %.d
	$(CC) $(CFLAGS) $(DEPFLAGS_STEM) -c -o$@ $<
	
$(DLL_OBJS) : %.o : $(SRC_PREFIX)%.c %.d
	$(CC) $(DLL_CFLAGS) $(DEPFLAGS_STEM) -c -o$@ $<

$(DEPS) : 
	
$(DLL_PATH) : dll/dllmain.o dll/hook_connect_win32.o dll/hook_connect_win32.o dll/hook_connect_cygwin.o dll/hook_createprocess_win32.o dll/hook_installer.o dll/ipc_client_and_child_data.o dll/dllutil_log_func.o dll/dllutil_wsock.o dll/remote_function/remote_function.o common.o common_wsock.o ipc_message.o log.o cygwin_strsafe/strsafe.o
	$(CC) -shared -o$@ -Wl,--out-implib=$(DLL_IMPLIB_PATH) -L$(LIB_PREFIX) $(filter %.c %.o %.a %.lib,$^) -lntdllcrt -lMinHookx64 -lws2_32 -lshlwapi
		
#	-Wl,--export-all-symbols \
#	-Wl,--enable-auto-import \
	
$(DLL_IMPLIB_PATH) : $(DLL_PATH)

$(EXEC_PATH) : exe/main.o exe/args_and_config.o exe/ipc_proc_bookkeeping.o common.o common_wsock.o ipc_message.o log.o cygwin_strsafe/strsafe.o $(DLL_IMPLIB_PATH)
	$(CC) -o$@ $^ -lntdllcrt -lkernel32 -lshlwapi -ladvapi32 -lcygwin -lws2_32

.PHONY : clean

clean :
	$(RM) $(ALL_EXECS)
	$(RM) $(ALL_SHARED_LIBS)
	$(RM) $(ALL_IMPLIBS)
	$(RM) $(OBJS)
	$(RM) $(DEPS)
	
rebuild : clean all
rebuildrelease : clean release
rebuilddebug : clean debug

include $(wildcard $(DEPS))
