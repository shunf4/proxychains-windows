SRC_PREFIX = ../src/
INCLUDE_PREFIX = ../include/
LIB_PREFIX = ../lib/

AUTO_SRCS = $(sort $(wildcard $(SRC_PREFIX)exe/*.c)) $(sort $(wildcard $(SRC_PREFIX)dll/*.c)) $(sort $(wildcard $(SRC_PREFIX)*.c))
SRCS = $(AUTO_SRCS) $(SRC_PREFIX)cygwin_strsafe/strsafe.c $(SRC_PREFIX)dll/remote_function/remote_function.c
#SRCS = $(sort $(wildcard $(SRC_PREFIX)dll/*.c)) $(sort $(wildcard $(SRC_PREFIX)*.c))
#SRCS = $(sort $(wildcard $(SRC_PREFIX)exe/*.c)) $(sort $(wildcard $(SRC_PREFIX)*.c))
AUTO_OBJS = $(patsubst $(SRC_PREFIX)%,%,$(AUTO_SRCS:.c=.o))
OBJS = $(patsubst $(SRC_PREFIX)%,%,$(SRCS:.c=.o))

DEPS = $(patsubst $(SRC_PREFIX)%,%,$(SRCS:.c=.d))

CFLAGS = -Wall -g -D_UNICODE -DUNICODE -D__STRSAFE__NO_INLINE -D__CRT_STRSAFE_IMPL -I$(INCLUDE_PREFIX)
CFLAGS_REMOTE_FUNCTION = -Wall -g -D_UNICODE -DUNICODE -D__STRSAFE__NO_INLINE -D__CRT_STRSAFE_IMPL -I$(INCLUDE_PREFIX)
CFLAGS_STRSAFE = -fgnu89-inline -Wall -Werror -g -D_UNICODE -DUNICODE -I$(INCLUDE_PREFIX)
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
	
cygwin_strsafe/strsafe.o : $(SRC_PREFIX)cygwin_strsafe/strsafe.c cygwin_strsafe/strsafe.d
	$(CC) $(CFLAGS_STRSAFE) $(DEPFLAGS_IN_PREREQ) -c -o$@ $<
	
dll/remote_function/remote_function.o : $(SRC_PREFIX)dll/remote_function/remote_function.c dll/remote_function/remote_function.d
	$(CC) $(CFLAGS_REMOTE_FUNCTION) $(DEPFLAGS_IN_PREREQ) -c -o$@ $<
	
$(DLL_PATH) : $(SRC_PREFIX)dll/dllmain.c dll/remote_function/remote_function.o common.o cygwin_strsafe/strsafe.o dll/dllmain.d
	$(CC) $(CFLAGS) $(DEPFLAGS_IN_PREREQ) -DPXCHDLL_EXPORTS -shared -o$@ \
		-Wl,--out-implib=$(DLL_IMPLIB_PATH) \
		$(filter %.c %.o %.a,$^) -L$(LIB_PREFIX) -lntdllcrt -lMinHookx64
		
	#	-Wl,--export-all-symbols \
	#	-Wl,--enable-auto-import \
	
$(DLL_IMPLIB_PATH) : $(DLL_PATH)

$(EXEC_PATH) : $(SRC_PREFIX)exe/main.c common.o log.o cygwin_strsafe/strsafe.o $(DLL_IMPLIB_PATH) exe/main.d
	$(CC) $(CFLAGS) $(DEPFLAGS_IN_PREREQ) -o$@ $(filter %.c %.o %.a,$^) -lntdllcrt -lkernel32 -lshlwapi -lcygwin

.PHONY : clean

clean :
	$(RM) $(ALL_EXECS)
	$(RM) $(ALL_SHARED_LIBS)
	$(RM) $(ALL_IMPLIBS)
	$(RM) $(OBJS)
	$(RM) $(DEPS)
	
rebuild : clean all

include $(wildcard $(DEPS))
