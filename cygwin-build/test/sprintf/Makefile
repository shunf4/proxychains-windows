SRCS=$(wildcard *.c)
BINS=$(addprefix _,$(basename $(SRCS)))

all : $(BINS)

.PHONY : clean

_sprintf : sprintf.c
	$(CC) -g -o_$(basename $^) $^

clean :
	$(RM) _*