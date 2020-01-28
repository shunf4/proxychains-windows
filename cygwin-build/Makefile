SRC_PREFIX = ../src/
INCLUDE_PREFIX = ../include/
LIB_PREFIX = ../lib/

SRCS = $(sort $(wildcard $(SRC_PREFIX)exe/*.c)) $(sort $(wildcard $(SRC_PREFIX)dll/*.c)) $(sort $(wildcard $(SRC_PREFIX)*.c))
#SRCS = $(sort $(wildcard $(SRC_PREFIX)dll/*.c)) $(sort $(wildcard $(SRC_PREFIX)*.c))
#SRCS = $(sort $(wildcard $(SRC_PREFIX)exe/*.c)) $(sort $(wildcard $(SRC_PREFIX)*.c))
OBJS = $(patsubst $(SRC_PREFIX)%,%,$(SRCS:.c=.o))

CFLAGS = -Wall -g -D_UNICODE -DUNICODE -D__STRSAFE__NO_INLINE -D__CRT_STRSAFE_IMPL -I$(INCLUDE_PREFIX)
CFLAGS_REMOTE_FUNCTION = -Wall -g -D_UNICODE -DUNICODE -D__STRSAFE__NO_INLINE -D__CRT_STRSAFE_IMPL -I$(INCLUDE_PREFIX)
CFLAGS_STRSAFE = -fgnu89-inline -Wall -Werror -g -D_UNICODE -DUNICODE -I$(INCLUDE_PREFIX)

EXEC_PATH = ./proxychains.exe
DLL_MODULE_NAME = proxychains_hook
DLL_PATH = ./cyg$(DLL_MODULE_NAME).dll
DLL_IMPLIB_PATH = ./lib$(DLL_MODULE_NAME).a

ALL_IMPLIBS = $(DLL_IMPLIB_PATH)
ALL_SHARED_LIBS = $(DLL_PATH)
ALL_EXECS = $(EXEC_PATH)

all : $(ALL_EXECS)

$(OBJS) : %.o : $(SRC_PREFIX)%.c
	$(CC) $(CFLAGS) -c -o$@ $<
	
cygwin_strsafe/strsafe.o : $(SRC_PREFIX)cygwin_strsafe/strsafe.c
	$(CC) $(CFLAGS_STRSAFE) -c -o$@ $<
	
dll/remote_function/remote_function.o : $(SRC_PREFIX)dll/remote_function/remote_function.c
	$(CC) $(CFLAGS_REMOTE_FUNCTION) -c -o$@ $<
	
$(DLL_PATH) : $(SRC_PREFIX)dll/dllmain.c dll/remote_function/remote_function.o common.o cygwin_strsafe/strsafe.o
	$(CC) $(CFLAGS) -DPXCHDLL_EXPORTS -shared -o$@ \
		-Wl,--out-implib=$(DLL_IMPLIB_PATH) \
		-Wl,--export-all-symbols \
		-Wl,--enable-auto-import \
		$^ -L$(LIB_PREFIX) -lntdllcrt -lMinHookx64
		
$(DLL_IMPLIB_PATH) : $(DLL_PATH)

$(EXEC_PATH) : $(SRC_PREFIX)exe/main.c common.o log.o cygwin_strsafe/strsafe.o $(DLL_IMPLIB_PATH)
	$(CC) $(CFLAGS) -o$@ $^ -lntdllcrt -lkernel32 -lshlwapi -lcygwin

.PHONY : clean

#_test1 : test1.c
#	$(CC) -std=gnu89 -g -o_$(basename $^) $^ -lntdllcrt

clean :
	$(RM) $(ALL_EXECS)
	$(RM) $(ALL_SHARED_LIBS)
	$(RM) $(ALL_IMPLIBS)
	$(RM) $(OBJS) cygwin_strsafe/strsafe.o dll/remote_function/remote_function.o
	
depend: .depend

.depend: $(SRCS)
	rm -f ./.depend
	$(CC) $(CFLAGS) -MM $^ -MF  ./.depend;

include .depend
