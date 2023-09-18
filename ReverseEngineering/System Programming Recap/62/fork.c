#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>

int main(){
	if(fork()){
		printf("nonzero\n");
	}
	else{
		printf("zero\n");	
	}

	printf("done\n");
		
	return 0;
}
