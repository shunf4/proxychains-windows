SRCS=$(wildcard *.c)
BINS=$(addprefix _,$(basename $(SRCS)))

all : $(BINS) px

.PHONY : clean

_test : test.c
	$(CC) -g -o_$(basename $^) $^

_ctrlc : ctrlc.c
	$(CC) -g -o_$(basename $^) $^

px :
	make -C ../../

clean :
	$(RM) _*