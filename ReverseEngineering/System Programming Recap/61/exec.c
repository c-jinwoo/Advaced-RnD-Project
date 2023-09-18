#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>



int main(){
	char *command[] = {"grep", "-E", "c$", "-", 0};
	char *bin_file = command[0];
	
	int redirect_fd = open("./redirect_fd.txt", O_CREAT | O_TRUNC | O_WRONLY, 0644);
	dup2(redirect_fd, STDOUT_FILENO);
	close(redirect_fd);

	if(execvp(bin_file, command) == -1){
		fprintf(stderr, "Error executing %s\n", bin_file);			
	}
	printf("done!\n");

	return 0;
}
