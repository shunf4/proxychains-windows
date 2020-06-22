SRCS=$(wildcard *.c)
BINS=$(addprefix _,$(basename $(SRCS)))

all : $(BINS)

.PHONY : clean

_test : test.c
	$(CC) -g -o_$(basename $^) $^

_test2 : test2.c
	$(CC) -g -o_$(basename $^) $^
	
_test3 : test3.c
	$(CC) -g -o_$(basename $^) $^
	
_test4 : test4.c
	$(CC) -g -o_$(basename $^) $^

_test5 : test5.c
	$(CC) -g -o_$(basename $^) $^

px :
	make -C ../../

clean :
	$(RM) _*