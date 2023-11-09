#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int64_t add(int64_t, int64_t);
int64_t sub(int64_t, int64_t);

int main(){
	const char *str = "static";
	printf("str: %p\n", str);
	printf("main: %p\n", main);

	// function pointer	
	int64_t (*function_pointer)(int64_t, int64_t);
	function_pointer = add;
	printf("1 + 2 = %ld\n", function_pointer(1, 2));
	function_pointer = sub;
	printf("1 - 2 = %ld\n", function_pointer(1, 2));

	return 0;
}

int64_t add(int64_t a, int64_t b){
	return a + b;
}

int64_t sub(int64_t a, int64_t b){
	return a - b;
}
