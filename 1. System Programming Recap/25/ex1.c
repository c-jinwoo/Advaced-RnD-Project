#include <stdio.h>

void bar(int);
void foo();

int main(){
	foo();
	bar(211);
	foo();

	return 0;
}

void bar(int x){
	printf("%d\n", x);
}

void foo(){
	int a;
	printf("%d\n", a);
}
