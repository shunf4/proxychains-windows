SRC_PREFIX = ../src/
INCLUDE_PREFIX = ../include/
LIB_PREFIX = ../lib/

SRCS = $(sort $(wildcard $(SRC_PREFIX)cygwin_strsafe/*.c)) $(sort $(wildcard $(SRC_PREFIX)exe/*.c)) $(sort $(wildcard $(SRC_PREFIX)dll/*.c)) $(sort $(wildcard $(SRC_PREFIX)dll/remote_function/*.c)) $(sort $(wildcard $(SRC_PREFIX)*.c))
OBJS = $(patsubst $(SRC_PREFIX)%,%,$(SRCS:.c=.o))

SPECIAL_SRCS = $(SRC_PREFIX)dll/dllmain.c

AUTO_SRCS = $(filter-out $(SPECIAL_SRCS),$(SRCS))
AUTO_OBJS = $(patsubst $(SRC_PREFIX)%,%,$(AUTO_SRCS:.c=.o))

DEPS = $(patsubst $(SRC_PREFIX)%,%,$(SRCS:.c=.d))

CFLAGS = -fgnu89-inline -Wall -g -D_UNICODE -DUNICODE -I$(INCLUDE_PREFIX)
DEPFLAGS_STEM = -MT $@ -MMD -MP -MF $*.d
DEPFLAGS_IN_PREREQ = -MT $@ -MMD -MP -MF $(filter %.d,$^)

EXEC_PATH = ./proxychains.exe
DLL_MODULE_NAME = proxychains_hook
DLL_PATH = ./cyg$(DLL_MODULE_NAME).dll
DLL_IMPLIB_PATH = ./lib$(DLL_MODULE_NAME).a

ALL_IMPLIBS = $(DLL_IMPLIB_PATH)
ALL_SHARED_LIBS = $(DLL_PATH)
ALL_EXECS = $(EXEC_PATH)

all : $(ALL_EXECS)

$(AUTO_OBJS) : %.o : $(SRC_PREFIX)%.c %.d
	$(CC) $(CFLAGS) $(DEPFLAGS_STEM) -c -o$@ $<
	
$(DEPS) : 
	
$(DLL_PATH) : $(SRC_PREFIX)dll/dllmain.c $(SRC_PREFIX)log_func_impl.c $(SRC_PREFIX)dll/hook_win32.c $(SRC_PREFIX)dll/hook_cygwin.c dll/remote_function/remote_function.o common.o ipc_message.o log.o cygwin_strsafe/strsafe.o dll/dllmain.d
	$(CC) $(CFLAGS) $(DEPFLAGS_IN_PREREQ) -shared -DPXCHDLL_EXPORTS -o$@ -Wl,--out-implib=$(DLL_IMPLIB_PATH) -L$(LIB_PREFIX) $(filter %.c %.o %.a %.lib,$^) -lntdllcrt -lMinHookx64 -lws2_32
		
#	-Wl,--export-all-symbols \
#	-Wl,--enable-auto-import \
	
$(DLL_IMPLIB_PATH) : $(DLL_PATH)

$(EXEC_PATH) : exe/main.o exe/args_and_config.o exe/ipc_proc_bookkeeping.o common.o ipc_message.o log.o cygwin_strsafe/strsafe.o $(DLL_IMPLIB_PATH)
	$(CC) -o$@ $^ -lntdllcrt -lkernel32 -lshlwapi -ladvapi32 -lcygwin -lws2_32

.PHONY : clean

clean :
	$(RM) $(ALL_EXECS)
	$(RM) $(ALL_SHARED_LIBS)
	$(RM) $(ALL_IMPLIBS)
	$(RM) $(OBJS)
	$(RM) $(DEPS)
	
rebuild : clean all

include $(wildcard $(DEPS))
