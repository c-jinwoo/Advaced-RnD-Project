#include <stdio.h>

char global = 1;

static char static_global = 2;

int main(){
	static char static_local = 3;

	char automatic = 4;

	printf("&global: %p\n", &global);
	printf("&static_global: %p\n", &static_global);
	printf("&static_local: %p\n", &static_local);
	printf("&automatic: %p\n", &automatic);

	return 0;
}
