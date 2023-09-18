#include <stdio.h>

int counter();

int main(){
	printf("%d\n", counter());
	printf("%d\n", counter());
	printf("%d\n", counter());

	return 0;
}

int counter(){
	static int count = 0;
	return ++count;
}
