SRCS=$(wildcard *.c)
BINS=$(addprefix _,$(basename $(SRCS)))

all : $(BINS)

.PHONY : clean

_sprintf : sprintf.c
	$(CC) -O2 -o_$(basename $^) $^

clean :
	$(RM) _*