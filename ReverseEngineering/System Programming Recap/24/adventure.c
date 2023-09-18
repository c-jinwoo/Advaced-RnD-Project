#include <stdio.h>

int main(){
	char starting_point = '.';
	char* hero = &starting_point;

	while(1){
		if(*hero == '\0'){
			putchar('\n');
		}
		else{
			putchar(*hero);
		}
		fflush(stdout);
		hero++;
	}

	return 0;
}
