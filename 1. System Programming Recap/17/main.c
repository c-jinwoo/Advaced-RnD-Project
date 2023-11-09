#include <stdio.h>

int main(){
	char src[] = "hello, world";
	char dst[sizeof(src)] = {0};
	printf("src:%s\n", src);

	return 0;
}
