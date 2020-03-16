#include <stdio.h>
#include <inttypes.h>

uint32_t swap_words(uint32_t arg)
{
	uint16_t* const sp = (uint16_t*)&arg;
	uint16_t hi = sp[0];
	uint16_t lo = sp[1];
	sp[1] = hi;
	sp[0] = lo;
	return arg;
}

int main() {
	uint32_t x = 0xffff0000;
	uint32_t y = swap_words(x);
	printf("%x\n", x);
	printf("%x\n", y);
	return 0;
}