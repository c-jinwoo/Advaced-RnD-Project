#include <stdio.h>

int main(){
	char a[] = "a";
	char* b = "b";//const char* b = "b";

	printf("a: %p\n", a);
	printf("b: %p\n", b);
	printf("&b: %p\n", &b);
	
	a[0] = 'A';
	printf("a: %s\n", a);

	b[0] = 'B';		// readonly : segfault
	printf("b: %s\n", b);

	return 0;
}
