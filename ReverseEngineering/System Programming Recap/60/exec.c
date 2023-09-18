#include <unistd.h>
#include <stdio.h>

int main(){
	char *command[] = {"grep", "-E", "c$", "-", 0};
	char *bin_file = command[0];
	
	if(execvp(bin_file, command) == -1){
		fprintf(stderr, "Error executing %s\n", bin_file);			}
		
	return 0;
}
