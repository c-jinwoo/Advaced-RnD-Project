#include <stdio.h>
#include <stdint.h>

int main(){
	char a = 'a';
	char b = 'b';

	printf("&a : %p\n", &a);
	printf("&b : %p\n", &b);

	uint16_t c = 1;
	uint16_t d = 2;

	printf("&c : %p\n", &c);
	printf("&d : %p\n", &d);

	uint32_t e = 1;
	uint32_t f = 2;

	printf("&e : %p\n", &e);
	printf("&f : %p\n", &f);

	return 0;
}
