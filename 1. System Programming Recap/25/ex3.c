#include <stdio.h>

int main(){
	int* p;
	
	{
		int i = 0;
		p = &i;
		printf("i: %d\n", i);
		printf("&i: %p\n", &i);
	}

	{
		int j = 1;
		printf("j: %d\n", j);
		printf("&j: %p\n", &j);
	}

	printf("*p: %d\n", *p);

	return 0;
}
